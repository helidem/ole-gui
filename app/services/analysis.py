from __future__ import annotations

from pathlib import Path

from app.analyzers.base import AnalyzerContext
from app.analyzers.registry import selected_analyzers
from app.config import APP_VERSION, DEFAULT_TOOLS
from app.models import AnalysisOptions, AnalysisResponse, AnalyzerResult, BulkAnalysisResponse, Severity, UploadedFileInfo
from app.services.risk import max_severity, summarize

PDF_TOOLS = ("pdf_static",)
OFFICE_TOOLS = ("oleid", "olevba", "mraptor", "objects")
PDF_EXTENSIONS = {".pdf"}
OFFICE_EXTENSIONS = {
    ".doc",
    ".docm",
    ".dot",
    ".dotm",
    ".xls",
    ".xlsm",
    ".xlsb",
    ".xlt",
    ".xltm",
    ".ppt",
    ".pptm",
    ".pot",
    ".potm",
    ".rtf",
    ".xml",
    ".mht",
    ".mhtml",
    ".zip",
}


def auto_tools_for_filename(filename: str) -> list[str]:
    suffix = Path(filename.lower()).suffix
    if suffix in PDF_EXTENSIONS:
        return list(PDF_TOOLS)
    if suffix in OFFICE_EXTENSIONS:
        return list(OFFICE_TOOLS)
    return list(DEFAULT_TOOLS)


def analyze_file(path: Path, file_info: UploadedFileInfo, options: AnalysisOptions) -> AnalysisResponse:
    tool_keys = options.tools or list(DEFAULT_TOOLS)
    context = AnalyzerContext(
        file_path=str(path),
        original_name=file_info.original_name,
        options=options,
    )
    results: list[AnalyzerResult] = []
    for analyzer in selected_analyzers(tool_keys):
        results.append(analyzer.analyze(context))

    risk = max_severity(results)
    return AnalysisResponse(
        app_version=APP_VERSION,
        file=file_info,
        risk=risk,
        summary=summarize(results, risk),
        results=results,
        selected_tools=list(tool_keys),
    )


def summarize_bulk(results: list[AnalysisResponse]) -> tuple[Severity, str]:
    if not results:
        return Severity.info, "No files analyzed."
    rank = {Severity.info: 0, Severity.low: 1, Severity.medium: 2, Severity.high: 3, Severity.error: 2}
    risk = max((item.risk for item in results), key=lambda severity: rank.get(severity, 0))
    by_risk = {severity.value: sum(1 for item in results if item.risk == severity) for severity in Severity}
    nonzero = ", ".join(f"{count} {name}" for name, count in by_risk.items() if count)
    return risk, f"Analyzed {len(results)} file(s). Risk breakdown: {nonzero}."


def build_bulk_response(results: list[AnalysisResponse]) -> BulkAnalysisResponse:
    risk, summary = summarize_bulk(results)
    return BulkAnalysisResponse(
        app_version=APP_VERSION,
        count=len(results),
        risk=risk,
        summary=summary,
        results=results,
    )

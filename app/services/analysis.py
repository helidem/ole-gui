from __future__ import annotations

from pathlib import Path
import shlex

from app.analyzers.base import AnalyzerContext
from app.analyzers.registry import selected_analyzers
from app.config import APP_VERSION, DEFAULT_TOOLS
from app.models import AnalysisOptions, AnalysisResponse, AnalyzerResult, BulkAnalysisResponse, Severity, UploadedFileInfo
from app.services.filetype import is_office_like, is_pdf, is_rtf
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


def command_line_for(
    tool_key: str,
    filename: str,
    options: AnalysisOptions,
    result: AnalyzerResult,
) -> str | None:
    """Build the native tool invocation without exposing submitted passwords."""
    if tool_key == "pdf_static":
        return None

    command = {
        "oleid": "oleid",
        "olevba": "olevba",
        "mraptor": "mraptor",
        "objects": "rtfobj" if result.data.get("tool") == "rtfobj" else "oleobj",
    }[tool_key]
    args = [command]
    if options.zip_password and tool_key in {"olevba", "mraptor", "objects"}:
        args.extend(["--zip", "$ZIP_PASSWORD"])
    if options.office_password and tool_key == "olevba":
        args.extend(["--password", "$OFFICE_PASSWORD"])
    if tool_key == "olevba":
        if not options.include_macro_source:
            args.append("--analysis")
        if options.include_decoded_strings:
            args.append("--decode")
    elif tool_key == "mraptor":
        args.append("--matches")
    args.append(filename)
    command = shlex.join(args)
    # shlex quotes dollar signs, but these two values are deliberately shell
    # environment-variable placeholders for secrets, not literal arguments.
    return command.replace("'$ZIP_PASSWORD'", '"$ZIP_PASSWORD"').replace(
        "'$OFFICE_PASSWORD'", '"$OFFICE_PASSWORD"'
    )


def auto_tools_for_filename(filename: str) -> list[str]:
    suffix = Path(filename.lower()).suffix
    if suffix in PDF_EXTENSIONS:
        return list(PDF_TOOLS)
    if suffix in OFFICE_EXTENSIONS:
        return list(OFFICE_TOOLS)
    return list(DEFAULT_TOOLS)


def auto_tools_for_file(path: Path, filename: str) -> list[str]:
    """Content-aware auto-selection; the filename heuristic is only a fallback."""
    if is_pdf(path, filename):
        return list(PDF_TOOLS)
    if is_office_like(path, filename) or is_rtf(path, filename):
        return list(OFFICE_TOOLS)
    return auto_tools_for_filename(filename)


def analyze_file(path: Path, file_info: UploadedFileInfo, options: AnalysisOptions) -> AnalysisResponse:
    tool_keys = options.tools or list(DEFAULT_TOOLS)
    context = AnalyzerContext(
        file_path=str(path),
        original_name=file_info.original_name,
        options=options,
    )
    results: list[AnalyzerResult] = []
    for analyzer in selected_analyzers(tool_keys):
        result = analyzer.analyze(context)
        result.command_line = command_line_for(analyzer.key, file_info.original_name, options, result)
        if analyzer.key == "pdf_static":
            result.command_line_note = (
                "No native command is available: PDF Static is a custom analyzer implemented by this app."
            )
        results.append(result)

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

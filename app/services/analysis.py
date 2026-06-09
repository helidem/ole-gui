from __future__ import annotations

from pathlib import Path

from app.analyzers.base import AnalyzerContext
from app.analyzers.registry import selected_analyzers
from app.config import APP_VERSION, DEFAULT_TOOLS
from app.models import AnalysisOptions, AnalysisResponse, AnalyzerResult, UploadedFileInfo
from app.services.risk import max_severity, summarize


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
    )

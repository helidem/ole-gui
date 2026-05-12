from __future__ import annotations

from app.models import AnalyzerResult, Severity


ORDER = {
    Severity.info: 0,
    Severity.low: 1,
    Severity.medium: 2,
    Severity.high: 3,
    Severity.error: 2,
}


def max_severity(results: list[AnalyzerResult]) -> Severity:
    highest = Severity.info
    for result in results:
        for finding in result.findings:
            if ORDER[finding.severity] > ORDER[highest]:
                highest = finding.severity
        if result.status == "error" and ORDER[Severity.error] > ORDER[highest]:
            highest = Severity.error
    return highest


def summarize(results: list[AnalyzerResult], risk: Severity) -> str:
    if risk == Severity.high:
        return "High-risk indicators were found. Treat the document as suspicious."
    if risk == Severity.medium:
        return "Potentially suspicious indicators were found. Review the details before opening."
    if risk == Severity.low:
        return "Low-risk indicators were found. The document still deserves normal caution."
    if risk == Severity.error:
        return "One or more analyzers failed. Review errors before trusting the result."
    return "No obvious malicious indicators were found by the enabled analyzers."

from __future__ import annotations

from app.analyzers.base import Analyzer, AnalyzerContext
from app.models import AnalyzerResult, Finding, Severity
from app.services.filetype import should_run_macro_analyzers


def _severity_from_risk(risk: object, value: object) -> Severity:
    text = str(risk or "").lower()
    if any(token in text for token in ("high", "danger", "malicious")):
        return Severity.high
    if any(token in text for token in ("medium", "suspicious", "warning")):
        return Severity.medium
    if "low" in text:
        return Severity.low
    if value is True:
        return Severity.low
    return Severity.info


def _clean_value(value: object) -> object:
    if isinstance(value, bytes):
        for encoding in ("utf-8", "cp949", "latin-1"):
            try:
                return value.decode(encoding)
            except UnicodeDecodeError:
                continue
        return value.decode("utf-8", errors="replace")
    return value


class OleIdAnalyzer(Analyzer):
    key = "oleid"
    label = "OleID: Document Indicators"
    description = "Identifies OLE traits such as macros, encryption, embedded objects, and Flash."

    def analyze(self, context: AnalyzerContext) -> AnalyzerResult:
        try:
            from oletools.oleid import OleID
        except Exception as exc:
            return AnalyzerResult(
                key=self.key,
                label=self.label,
                status="error",
                summary="oleid is unavailable.",
                findings=[Finding(analyzer=self.key, title="Import failed", severity=Severity.error, detail=str(exc))],
            )

        indicators = OleID(context.file_path).check()
        macro_capable = should_run_macro_analyzers(context.file_path, context.original_name)
        rows: list[dict[str, object]] = []
        findings: list[Finding] = []
        for indicator in indicators:
            value = _clean_value(getattr(indicator, "value", None))
            risk = getattr(indicator, "risk", None)
            row = {
                "id": getattr(indicator, "id", None),
                "name": getattr(indicator, "name", "Indicator"),
                "value": value,
                "risk": str(risk) if risk is not None else None,
                "description": getattr(indicator, "description", None),
            }
            rows.append(row)
            is_macro_indicator = str(row["id"]).lower() in {"vba", "xlm"}
            severity = Severity.info if is_macro_indicator and not macro_capable else _severity_from_risk(risk, value)
            if severity != Severity.info:
                findings.append(Finding(
                    analyzer=self.key,
                    title=str(row["name"]),
                    severity=severity,
                    detail=row["description"],
                    value=value,
                ))

        macro = next((r for r in rows if str(r.get("name")).lower() == "vba macros"), None)
        summary = "OLE indicators checked."
        if macro is not None and macro_capable:
            summary = "VBA macros detected." if macro.get("value") else "No VBA macros reported by oleid."
        elif not macro_capable:
            summary = "Input does not look like an Office/RTF container or macro source file."

        return AnalyzerResult(
            key=self.key,
            label=self.label,
            summary=summary,
            findings=findings,
            data={"indicators": rows},
        )

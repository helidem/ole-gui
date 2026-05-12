from __future__ import annotations

from app.analyzers.base import Analyzer, AnalyzerContext
from app.models import AnalyzerResult, Finding, Severity
from app.services.filetype import should_run_macro_analyzers


TYPE_SEVERITY = {
    "autoexec": Severity.high,
    "suspicious": Severity.high,
    "ioc": Severity.medium,
    "hex string": Severity.medium,
    "base64 string": Severity.medium,
    "dridex string": Severity.medium,
    "vba string": Severity.medium,
}


class OleVbaAnalyzer(Analyzer):
    key = "olevba"
    label = "OleVBA: Macro Analysis"
    description = "Detects, extracts, and analyzes VBA/XLM macros and obfuscated strings."

    def analyze(self, context: AnalyzerContext) -> AnalyzerResult:
        if not should_run_macro_analyzers(context.file_path, context.original_name):
            return AnalyzerResult(
                key=self.key,
                label=self.label,
                status="skipped",
                summary="Skipped because the upload is not an Office/RTF container or macro source file.",
            )

        try:
            from oletools.olevba import VBA_Parser
        except Exception as exc:
            return AnalyzerResult(
                key=self.key,
                label=self.label,
                status="error",
                summary="olevba is unavailable.",
                findings=[Finding(analyzer=self.key, title="Import failed", severity=Severity.error, detail=str(exc))],
            )

        parser = None
        try:
            kwargs = {}
            if context.options.zip_password:
                kwargs["zip_password"] = context.options.zip_password
            if context.options.office_password:
                kwargs["password"] = context.options.office_password
            try:
                parser = VBA_Parser(context.file_path, **kwargs)
            except TypeError:
                parser = VBA_Parser(context.file_path)

            has_macros = bool(parser.detect_vba_macros())
            macros = []
            if has_macros and context.options.include_macro_source:
                for filename, stream_path, vba_filename, code in parser.extract_macros():
                    macros.append({
                        "container": filename,
                        "stream_path": stream_path,
                        "module": vba_filename,
                        "code": code,
                    })

            analysis = []
            findings: list[Finding] = []
            if has_macros:
                for item_type, keyword, description in parser.analyze_macros():
                    normalized = str(item_type).strip().lower()
                    severity = TYPE_SEVERITY.get(normalized, Severity.low)
                    analysis.append({
                        "type": item_type,
                        "keyword": keyword,
                        "description": description,
                        "severity": severity,
                    })
                    findings.append(Finding(
                        analyzer=self.key,
                        title=f"{item_type}: {keyword}",
                        severity=severity,
                        detail=description,
                    ))

            summary = "VBA macros detected and analyzed." if has_macros else "No VBA macros detected."
            return AnalyzerResult(
                key=self.key,
                label=self.label,
                summary=summary,
                findings=findings,
                data={
                    "has_macros": has_macros,
                    "analysis": analysis,
                    "macros": macros if context.options.include_macro_source else [],
                },
            )
        except Exception as exc:
            return AnalyzerResult(
                key=self.key,
                label=self.label,
                status="error",
                summary="olevba analysis failed.",
                findings=[Finding(analyzer=self.key, title="Analysis failed", severity=Severity.error, detail=str(exc))],
            )
        finally:
            if parser is not None:
                parser.close()

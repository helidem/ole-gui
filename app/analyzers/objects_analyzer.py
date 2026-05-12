from __future__ import annotations

import subprocess

from app.analyzers.base import Analyzer, AnalyzerContext
from app.analyzers.cli_analyzer import cli_error_result, password_args, run_module
from app.models import AnalyzerResult, Finding, Severity


class ObjectsAnalyzer(Analyzer):
    key = "objects"
    label = "OleObj/RtfObj: Embedded Objects"
    description = "Reports embedded OLE/package objects using oleobj or rtfobj."

    def analyze(self, context: AnalyzerContext) -> AnalyzerResult:
        suffix = context.original_name.lower().rsplit(".", 1)[-1] if "." in context.original_name else ""
        module = "oletools.rtfobj" if suffix == "rtf" else "oletools.oleobj"
        label = "rtfobj" if suffix == "rtf" else "oleobj"
        try:
            code, output = run_module(module, [*password_args(context), context.file_path])
        except (subprocess.TimeoutExpired, Exception) as exc:
            return cli_error_result(self.key, self.label, exc)

        lowered = output.lower()
        findings = []
        if "external link" in lowered or "found relationship" in lowered:
            findings.append(Finding(
                analyzer=self.key,
                title="External relationship link",
                severity=Severity.medium,
                detail=f"{label} reported an external link relationship.",
            ))
        embedded_indicators = (
            "extract file embedded in ole object",
            "parsing ole package",
            "ole package",
            "executable",
            ".exe",
            ".js",
            ".vbs",
            ".lnk",
        )
        if any(token in lowered for token in embedded_indicators):
            findings.append(Finding(
                analyzer=self.key,
                title="Embedded object indicators",
                severity=Severity.medium,
                detail=f"{label} reported object-related content.",
            ))

        status = "error" if code not in (0, 1) and "error" in lowered else "ok"
        return AnalyzerResult(
            key=self.key,
            label=self.label,
            status=status,
            summary=f"{label} completed.",
            findings=findings,
            raw_output=output,
            data={"tool": label, "exit_code": code},
        )

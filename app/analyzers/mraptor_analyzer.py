from __future__ import annotations

import subprocess

from app.analyzers.base import Analyzer, AnalyzerContext
from app.analyzers.cli_analyzer import cli_error_result, password_args, run_module
from app.models import AnalyzerResult, Finding, Severity
from app.services.filetype import should_run_macro_analyzers


class MRaptorAnalyzer(Analyzer):
    key = "mraptor"
    label = "MacroRaptor: Macro Heuristics"
    description = "Uses A/W/X heuristics to flag malicious VBA macro behavior."

    def analyze(self, context: AnalyzerContext) -> AnalyzerResult:
        if not should_run_macro_analyzers(context.file_path, context.original_name):
            return AnalyzerResult(
                key=self.key,
                label=self.label,
                status="skipped",
                summary="Skipped because the upload is not an Office/RTF container or macro source file.",
            )

        try:
            code, output = run_module(
                "oletools.mraptor",
                [*password_args(context), "-m", context.file_path],
            )
        except (subprocess.TimeoutExpired, Exception) as exc:
            return cli_error_result(self.key, self.label, exc)

        severity = Severity.info
        title = "MacroRaptor completed"
        if code == 20 or "suspicious" in output.lower():
            severity = Severity.high
            title = "Suspicious macro behavior"
        elif code == 2:
            severity = Severity.low
            title = "Macros present without malicious heuristic match"
        elif code == 10:
            severity = Severity.error
            title = "MacroRaptor returned an error"

        findings = []
        if severity != Severity.info:
            findings.append(Finding(analyzer=self.key, title=title, severity=severity))

        return AnalyzerResult(
            key=self.key,
            label=self.label,
            status="error" if severity == Severity.error else "ok",
            summary=title,
            findings=findings,
            raw_output=output,
            data={"exit_code": code},
        )

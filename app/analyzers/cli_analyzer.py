from __future__ import annotations

import subprocess
import sys

from app.analyzers.base import AnalyzerContext
from app.config import ANALYZER_TIMEOUT_SECONDS
from app.models import AnalyzerResult, Finding, Severity


def run_module(module: str, args: list[str], cwd: str | None = None) -> tuple[int, str]:
    completed = subprocess.run(
        [sys.executable, "-m", module, *args],
        check=False,
        capture_output=True,
        text=True,
        timeout=ANALYZER_TIMEOUT_SECONDS,
        cwd=cwd,
    )
    output = "\n".join(part for part in (completed.stdout, completed.stderr) if part).strip()
    return completed.returncode, output


def password_args(context: AnalyzerContext) -> list[str]:
    args: list[str] = []
    if context.options.zip_password:
        args.extend(["-z", context.options.zip_password])
    return args


def cli_error_result(key: str, label: str, exc: Exception) -> AnalyzerResult:
    return AnalyzerResult(
        key=key,
        label=label,
        status="error",
        summary=f"{label} failed to run.",
        findings=[Finding(analyzer=key, title="Tool execution failed", severity=Severity.error, detail=str(exc))],
    )

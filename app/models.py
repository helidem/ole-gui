from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    error = "error"


class Finding(BaseModel):
    analyzer: str
    title: str
    severity: Severity = Severity.info
    detail: str | None = None
    value: Any | None = None


class AnalyzerResult(BaseModel):
    key: str
    label: str
    status: Literal["ok", "skipped", "error"] = "ok"
    summary: str
    findings: list[Finding] = Field(default_factory=list)
    data: dict[str, Any] = Field(default_factory=dict)
    raw_output: str | None = None


class UploadedFileInfo(BaseModel):
    original_name: str
    stored_name: str
    size: int
    content_type: str | None = None


class AnalysisOptions(BaseModel):
    tools: list[str] = Field(default_factory=list)
    zip_password: str | None = None
    office_password: str | None = None
    include_macro_source: bool = True
    include_decoded_strings: bool = True


class AnalysisResponse(BaseModel):
    app_version: str
    file: UploadedFileInfo
    risk: Severity
    summary: str
    results: list[AnalyzerResult]

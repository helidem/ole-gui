from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from app.models import AnalysisOptions, AnalyzerResult


@dataclass(frozen=True)
class AnalyzerContext:
    file_path: str
    original_name: str
    options: AnalysisOptions


class Analyzer(ABC):
    key: str
    label: str
    description: str

    @abstractmethod
    def analyze(self, context: AnalyzerContext) -> AnalyzerResult:
        """Analyze a file and return a serializable result."""

from __future__ import annotations

from app.analyzers.base import Analyzer
from app.analyzers.mraptor_analyzer import MRaptorAnalyzer
from app.analyzers.objects_analyzer import ObjectsAnalyzer
from app.analyzers.oleid_analyzer import OleIdAnalyzer
from app.analyzers.olevba_analyzer import OleVbaAnalyzer


ANALYZERS: dict[str, Analyzer] = {
    analyzer.key: analyzer
    for analyzer in (
        OleIdAnalyzer(),
        OleVbaAnalyzer(),
        MRaptorAnalyzer(),
        ObjectsAnalyzer(),
    )
}


def selected_analyzers(keys: list[str]) -> list[Analyzer]:
    return [ANALYZERS[key] for key in keys if key in ANALYZERS]

from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.analyzers.base import AnalyzerContext
from app.analyzers.registry import ANALYZERS
from app.models import AnalysisOptions


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run one Oletools GUI analyzer from the terminal.")
    parser.add_argument("--tool", required=True, choices=sorted(ANALYZERS))
    parser.add_argument("--zip-password")
    parser.add_argument("--office-password")
    parser.add_argument("--no-macro-source", action="store_true")
    parser.add_argument("--no-decoded-strings", action="store_true")
    parser.add_argument("file", help="Document to analyze")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    path = Path(args.file)
    if not path.is_file():
        raise SystemExit(f"File not found: {path}")

    options = AnalysisOptions(
        tools=[args.tool],
        zip_password=args.zip_password,
        office_password=args.office_password,
        include_macro_source=not args.no_macro_source,
        include_decoded_strings=not args.no_decoded_strings,
    )
    result = ANALYZERS[args.tool].analyze(AnalyzerContext(
        file_path=str(path),
        original_name=path.name,
        options=options,
    ))
    payload = result.model_dump(mode="json") if hasattr(result, "model_dump") else json.loads(result.json())
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 1 if result.status == "error" else 0


if __name__ == "__main__":
    raise SystemExit(main())

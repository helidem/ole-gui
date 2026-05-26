from __future__ import annotations

from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[1]
STATIC_DIR = BASE_DIR / "static"
UPLOAD_DIR = BASE_DIR / "uploads"

MAX_UPLOAD_BYTES = 64 * 1024 * 1024
ANALYZER_TIMEOUT_SECONDS = 45

DEFAULT_TOOLS = ("oleid", "olevba", "mraptor", "objects", "pdf_static")

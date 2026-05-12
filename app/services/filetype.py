from __future__ import annotations

from pathlib import Path


OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
ZIP_MAGIC = b"PK\x03\x04"
RTF_MAGIC = b"{\\rtf"
TEXT_MACRO_SUFFIXES = {".bas", ".cls", ".frm", ".vba", ".vb", ".vbs"}
TEXT_CONTAINER_SUFFIXES = {".xml", ".mht", ".mhtml", ".slk"}


def read_head(path: str | Path, size: int = 8192) -> bytes:
    with Path(path).open("rb") as handle:
        return handle.read(size)


def is_office_like(path: str | Path, original_name: str) -> bool:
    head = read_head(path)
    lower_name = original_name.lower()
    suffix = Path(lower_name).suffix
    return (
        head.startswith(OLE_MAGIC)
        or head.startswith(ZIP_MAGIC)
        or head.lstrip().startswith(RTF_MAGIC)
        or suffix in TEXT_CONTAINER_SUFFIXES
    )


def is_rtf(path: str | Path, original_name: str) -> bool:
    return read_head(path).lstrip().startswith(RTF_MAGIC) or Path(original_name.lower()).suffix == ".rtf"


def is_probable_macro_source(path: str | Path, original_name: str) -> bool:
    suffix = Path(original_name.lower()).suffix
    if suffix in TEXT_MACRO_SUFFIXES:
        return True

    head = read_head(path, 32768)
    if b"\x00" in head:
        return False
    try:
        text = head.decode("utf-8", errors="ignore").lower()
    except UnicodeDecodeError:
        return False

    declarations = ("sub ", "function ", "private sub", "public sub", "attribute vb_")
    script_markers = ("createobject(", "wscript.", "cscript.", "vbscript")
    return any(marker in text for marker in declarations) or any(marker in text for marker in script_markers)


def should_run_macro_analyzers(path: str | Path, original_name: str) -> bool:
    if is_rtf(path, original_name):
        return is_probable_macro_source(path, original_name)
    return is_office_like(path, original_name) or is_probable_macro_source(path, original_name)

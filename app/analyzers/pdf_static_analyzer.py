from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any

from app.analyzers.base import Analyzer, AnalyzerContext
from app.models import AnalyzerResult, Finding, Severity
from app.services.filetype import is_pdf


KEYWORDS: tuple[str, ...] = (
    "obj",
    "endobj",
    "stream",
    "endstream",
    "xref",
    "trailer",
    "startxref",
    "/Page",
    "/Encrypt",
    "/ObjStm",
    "/JS",
    "/JavaScript",
    "/AA",
    "/OpenAction",
    "/AcroForm",
    "/XFA",
    "/RichMedia",
    "/Launch",
    "/EmbeddedFile",
    "/Filespec",
    "/URI",
    "/SubmitForm",
    "/GoToE",
    "/GoToR",
    "/ImportData",
    "/JBIG2Decode",
)

HIGH_RISK_KEYWORDS = {
    "/Launch": "Launch action can start an external application.",
    "/EmbeddedFile": "Embedded files can hide payloads inside the PDF.",
    "/Filespec": "File specifications often accompany embedded or external file actions.",
    "/OpenAction": "OpenAction runs automatically when the document is opened.",
    "/AA": "Additional actions can trigger from page or field events.",
    "/JavaScript": "Embedded JavaScript is a common malicious PDF technique.",
    "/JS": "Short JavaScript action key is present.",
    "/XFA": "XFA forms support scripting and complex form behavior.",
    "/RichMedia": "Rich media content can expose legacy viewer attack surface.",
}

MEDIUM_RISK_KEYWORDS = {
    "/AcroForm": "Interactive form content is present.",
    "/SubmitForm": "Form submission action may exfiltrate data.",
    "/GoToE": "Embedded-file navigation action is present.",
    "/GoToR": "Remote go-to action references external content.",
    "/ImportData": "ImportData action can load external form data.",
    "/URI": "URI actions or links are present.",
    "/ObjStm": "Object streams can hide objects from simple scanners.",
    "/Encrypt": "Encrypted PDFs can obscure content from static analysis.",
    "/JBIG2Decode": "JBIG2 streams are worth reviewing for exploit-era samples.",
}

SUSPICIOUS_URI_SCHEMES = ("http://", "https://", "ftp://", "file://", "mailto:")
NAME_TOKEN_RE = re.compile(rb"/(?:#(?:[0-9A-Fa-f]{2})|[^\s<>\[\]\(\)/%#])+")
URI_RE = re.compile(
    rb"(?:(?:https?|ftp|file)://|mailto:)[^\s<>\]\[()\"']{3,}",
    re.IGNORECASE,
)
INFO_FIELD_RE = re.compile(rb"/(Title|Author|Creator|Producer|CreationDate|ModDate)\s*(\((?:\\.|[^\\)]){0,500}\)|<[^>]{0,1000}>)")


def _decode_pdf_name(token: bytes) -> str:
    def replace(match: re.Match[bytes]) -> bytes:
        return bytes([int(match.group(1), 16)])

    decoded = re.sub(rb"#([0-9A-Fa-f]{2})", replace, token)
    return decoded.decode("latin-1", errors="replace")


def _count_keywords(data: bytes) -> tuple[list[dict[str, Any]], list[str]]:
    exact_counts = {keyword: data.count(keyword.encode("latin-1")) for keyword in KEYWORDS}
    name_counts = Counter(_decode_pdf_name(match.group(0)) for match in NAME_TOKEN_RE.finditer(data))
    rows: list[dict[str, Any]] = []
    obfuscated: list[str] = []

    for keyword in KEYWORDS:
        decoded_count = name_counts.get(keyword, 0) if keyword.startswith("/") else exact_counts[keyword]
        exact_count = exact_counts[keyword]
        if keyword.startswith("/") and decoded_count > exact_count:
            obfuscated.append(keyword)
        rows.append(
            {
                "keyword": keyword,
                "count": max(exact_count, decoded_count),
                "obfuscated": decoded_count > exact_count,
            }
        )
    return rows, obfuscated


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _pdf_string(value: bytes) -> str:
    if value.startswith(b"<") and value.endswith(b">"):
        try:
            return bytes.fromhex(value[1:-1].decode("ascii", errors="ignore")).decode("utf-16-be", errors="ignore")
        except ValueError:
            return value.decode("latin-1", errors="replace")
    inner = value[1:-1] if value.startswith(b"(") and value.endswith(b")") else value
    return inner.replace(rb"\)", b")").replace(rb"\(", b"(").decode("latin-1", errors="replace")


def _extract_metadata(data: bytes) -> list[dict[str, str]]:
    rows = []
    seen = set()
    for match in INFO_FIELD_RE.finditer(data):
        key = match.group(1).decode("ascii")
        if key in seen:
            continue
        rows.append({"field": key, "value": _pdf_string(match.group(2))[:300]})
        seen.add(key)
    return rows


def _extract_uris(data: bytes, limit: int = 25) -> list[dict[str, str]]:
    uris = []
    seen = set()
    for match in URI_RE.finditer(data):
        uri = match.group(0).rstrip(b">.").decode("latin-1", errors="replace")
        if uri in seen:
            continue
        seen.add(uri)
        uris.append({"uri": uri[:500]})
        if len(uris) >= limit:
            break
    return uris


def _version(data: bytes) -> str | None:
    match = re.search(rb"%PDF-(\d\.\d)", data[:1024])
    return match.group(1).decode("ascii") if match else None


def _hashes(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),  # nosec B324 - forensic file fingerprint, not security control
        "sha1": hashlib.sha1(data).hexdigest(),  # nosec B324 - forensic file fingerprint, not security control
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _pymupdf_details(path: str, password: str | None) -> dict[str, Any]:
    try:
        import fitz  # type: ignore[import-not-found]
    except Exception as exc:
        return {"available": False, "error": f"PyMuPDF unavailable: {exc}"}

    try:
        with fitz.open(path) as doc:
            authenticated = True
            if doc.needs_pass:
                authenticated = bool(password and doc.authenticate(password))
            details: dict[str, Any] = {
                "available": True,
                "page_count": doc.page_count,
                "is_encrypted": bool(doc.is_encrypted),
                "needs_password": bool(doc.needs_pass),
                "authenticated": authenticated,
                "metadata": {k: v for k, v in (doc.metadata or {}).items() if v},
            }
            if authenticated:
                embedded = []
                for index in range(getattr(doc, "embfile_count", lambda: 0)()):
                    info = doc.embfile_info(index)
                    embedded.append(
                        {
                            "name": info.get("filename") or info.get("ufilename") or f"embedded-{index}",
                            "size": info.get("size"),
                            "description": info.get("desc"),
                        }
                    )
                details["embedded_files"] = embedded
            return details
    except Exception as exc:
        return {"available": True, "error": str(exc)}


class PdfStaticAnalyzer(Analyzer):
    key = "pdf_static"
    label = "PDF Static: Structure and Actions"
    description = "Triages PDFs for JavaScript, launch actions, embedded files, URIs, encryption, object streams, and metadata."

    def analyze(self, context: AnalyzerContext) -> AnalyzerResult:
        if not is_pdf(context.file_path, context.original_name):
            return AnalyzerResult(
                key=self.key,
                label=self.label,
                status="skipped",
                summary="Input does not look like a PDF.",
            )

        data = Path(context.file_path).read_bytes()
        keyword_rows, obfuscated = _count_keywords(data)
        keyword_counts = {row["keyword"]: int(row["count"]) for row in keyword_rows}
        uris = _extract_uris(data)
        eof_count = data.count(b"%%EOF")
        xref_count = len(re.findall(rb"\bxref\b", data))
        trailer_count = data.count(b"trailer")
        findings: list[Finding] = []

        for keyword, detail in HIGH_RISK_KEYWORDS.items():
            count = keyword_counts.get(keyword, 0)
            if count:
                findings.append(
                    Finding(
                        analyzer=self.key,
                        title=f"{keyword} present",
                        severity=Severity.high,
                        detail=detail,
                        value=count,
                    )
                )

        for keyword, detail in MEDIUM_RISK_KEYWORDS.items():
            count = keyword_counts.get(keyword, 0)
            if count:
                findings.append(
                    Finding(
                        analyzer=self.key,
                        title=f"{keyword} present",
                        severity=Severity.medium,
                        detail=detail,
                        value=count,
                    )
                )

        if obfuscated:
            findings.append(
                Finding(
                    analyzer=self.key,
                    title="Hex-obfuscated PDF names",
                    severity=Severity.medium,
                    detail="PDF names used #xx escaping, a common way to hide suspicious keywords from simple scanners.",
                    value=", ".join(obfuscated),
                )
            )

        if eof_count > 1 or xref_count > 1 or trailer_count > 1:
            findings.append(
                Finding(
                    analyzer=self.key,
                    title="Incremental updates or appended revisions",
                    severity=Severity.low,
                    detail="Multiple EOF, xref, or trailer markers can indicate saved revisions or appended content.",
                    value={"eof": eof_count, "xref": xref_count, "trailer": trailer_count},
                )
            )

        if any(row["uri"].lower().startswith(SUSPICIOUS_URI_SCHEMES) for row in uris):
            findings.append(
                Finding(
                    analyzer=self.key,
                    title="External URI references",
                    severity=Severity.medium,
                    detail="The PDF contains links or URI actions that should be reviewed.",
                    value=len(uris),
                )
            )

        pymupdf = _pymupdf_details(context.file_path, context.options.office_password)
        embedded_files = pymupdf.get("embedded_files") if isinstance(pymupdf.get("embedded_files"), list) else []
        if embedded_files and not keyword_counts.get("/EmbeddedFile"):
            findings.append(
                Finding(
                    analyzer=self.key,
                    title="Embedded files reported by PyMuPDF",
                    severity=Severity.high,
                    detail="The PDF contains embedded file entries.",
                    value=len(embedded_files),
                )
            )

        summary = "PDF static triage completed."
        if findings:
            summary = f"PDF static triage found {len(findings)} indicators."

        data_payload: dict[str, Any] = {
            "file": {
                "version": _version(data),
                "size": len(data),
                "entropy": round(_entropy(data), 3),
                **_hashes(data),
            },
            "structure": [
                {"name": "%%EOF", "count": eof_count},
                {"name": "xref", "count": xref_count},
                {"name": "trailer", "count": trailer_count},
            ],
            "keyword_counts": keyword_rows,
            "uris": uris,
            "metadata": _extract_metadata(data),
            "pymupdf": pymupdf,
        }
        if embedded_files:
            data_payload["embedded_files"] = embedded_files

        return AnalyzerResult(
            key=self.key,
            label=self.label,
            summary=summary,
            findings=findings,
            data=data_payload,
        )

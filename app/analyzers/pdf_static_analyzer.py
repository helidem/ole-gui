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
HIGH_RISK_ACTION_TYPES = {"/JavaScript", "/Launch"}
MEDIUM_RISK_ACTION_TYPES = {"/URI", "/SubmitForm", "/GoToR", "/GoToE", "/ImportData"}
ADDITIONAL_ACTION_EVENTS = {
    "/O": "page opened",
    "/C": "page closed",
    "/E": "cursor enters annotation area",
    "/X": "cursor exits annotation area",
    "/D": "mouse button pressed/down",
    "/U": "mouse button released/up",
    "/Fo": "field receives focus",
    "/Bl": "field loses focus",
    "/PO": "page opened (page object)",
    "/PC": "page closed (page object)",
    "/PV": "page becomes visible",
    "/PI": "page becomes invisible",
    "/K": "keystroke in text field",
    "/F": "field formatting",
    "/V": "field value changed",
}
HIGH_RISK_EMBEDDED_EXTENSIONS = {
    ".exe",
    ".dll",
    ".scr",
    ".com",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".jse",
    ".wsf",
    ".hta",
    ".lnk",
    ".jar",
    ".iso",
    ".img",
}
MEDIUM_RISK_EMBEDDED_EXTENSIONS = {
    ".doc",
    ".docm",
    ".xls",
    ".xlsm",
    ".xlsb",
    ".ppt",
    ".pptm",
    ".rtf",
    ".pdf",
    ".zip",
    ".rar",
    ".7z",
}
PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{4,}")
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


def _magic_type(data: bytes) -> str:
    signatures = (
        (b"MZ", "Windows executable / DLL"),
        (b"%PDF-", "PDF document"),
        (b"PK\x03\x04", "ZIP / OOXML / JAR archive"),
        (b"PK\x05\x06", "empty ZIP archive"),
        (b"PK\x07\x08", "spanned ZIP archive"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE / legacy Office document"),
        (b"{\\rtf", "RTF document"),
        (b"\x7fELF", "ELF executable"),
        (b"\x1f\x8b", "GZIP archive"),
        (b"Rar!", "RAR archive"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    )
    for prefix, label in signatures:
        if data.startswith(prefix):
            return label
    if data[:256].lstrip().lower().startswith((b"<html", b"<!doctype html")):
        return "HTML document"
    if data[:256].lstrip().lower().startswith((b"function ", b"var ", b"let ", b"const ", b"//", b"/*")):
        return "JavaScript / script text"
    return "unknown"


def _printable_preview(data: bytes, limit: int = 5) -> list[str]:
    preview: list[str] = []
    for match in PRINTABLE_RE.finditer(data[:8192]):
        value = match.group(0).decode("latin-1", errors="replace").strip()
        if value:
            preview.append(value[:160])
        if len(preview) >= limit:
            break
    return preview


def _embedded_file_risk(name: str, magic: str, entropy: float) -> tuple[str, str]:
    suffix = Path(name.lower()).suffix
    if suffix in HIGH_RISK_EMBEDDED_EXTENSIONS or "executable" in magic.lower():
        return "high", "Embedded payload has an executable/script/disk-image extension or executable magic bytes."
    if suffix in MEDIUM_RISK_EMBEDDED_EXTENSIONS or magic != "unknown":
        return "medium", "Embedded payload is a document/archive or has identifiable active-content file magic."
    if entropy >= 7.5:
        return "medium", "Embedded payload has high entropy and may be compressed, encrypted, or packed."
    return "low", "Embedded payload present; review filename, hashes, and preview."


def _analyze_embedded_payload(index: int, info: dict[str, Any], payload: bytes) -> dict[str, Any]:
    name = info.get("filename") or info.get("ufilename") or f"embedded-{index}"
    magic = _magic_type(payload)
    entropy = round(_entropy(payload), 3)
    severity, reason = _embedded_file_risk(str(name), magic, entropy)
    return {
        "index": index,
        "name": str(name),
        "size": len(payload),
        "declared_size": info.get("size"),
        "description": info.get("desc"),
        "created": info.get("creationDate"),
        "modified": info.get("modDate"),
        "magic": magic,
        "entropy": entropy,
        "risk": severity,
        "risk_reason": reason,
        "first_bytes_hex": payload[:32].hex(" "),
        "printable_preview": _printable_preview(payload),
        **_hashes(payload),
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
                    try:
                        payload = doc.embfile_get(index)
                        embedded.append(_analyze_embedded_payload(index, info, payload))
                    except Exception as exc:
                        name = info.get("filename") or info.get("ufilename") or f"embedded-{index}"
                        embedded.append(
                            {
                                "index": index,
                                "name": str(name),
                                "size": info.get("size"),
                                "description": info.get("desc"),
                                "risk": "medium",
                                "risk_reason": f"Embedded file is present but could not be extracted for analysis: {exc}",
                            }
                        )
                details["embedded_files"] = embedded
            return details
    except Exception as exc:
        return {"available": True, "error": str(exc)}


def _page_number_for_ref(reader: Any, ref: Any) -> int | None:
    ref_id = getattr(ref, "idnum", None)
    ref_gen = getattr(ref, "generation", None)
    if ref_id is None:
        return None
    for index, page in enumerate(reader.pages, start=1):
        page_ref = getattr(page, "indirect_reference", None) or getattr(page, "indirectRef", None)
        if getattr(page_ref, "idnum", None) == ref_id and getattr(page_ref, "generation", None) == ref_gen:
            return index
    return None


def _open_action_value(value: Any, reader: Any | None = None, depth: int = 0) -> Any:
    if depth > 4:
        return str(value)
    if value is None:
        return None
    if hasattr(value, "get_object") and value.__class__.__name__ == "IndirectObject":
        object_ref = f"{value.idnum} {value.generation} R"
        page_number = _page_number_for_ref(reader, value) if reader is not None else None
        if page_number:
            return {"object_ref": object_ref, "type": "page", "page_number": page_number}
        resolved = value.get_object()
        serialized = _open_action_value(resolved, reader, depth + 1)
        if isinstance(serialized, dict):
            serialized.setdefault("object_ref", object_ref)
        return serialized
    if isinstance(value, dict):
        return {str(key): _open_action_value(item, reader, depth + 1) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_open_action_value(item, reader, depth + 1) for item in value]
    class_name = value.__class__.__name__
    if class_name == "NullObject":
        return None
    return str(value)


def _describe_open_action(raw_action: Any, reader: Any) -> dict[str, Any]:
    serialized = _open_action_value(raw_action, reader)
    details: dict[str, Any] = {"present": True, "raw": serialized}

    if isinstance(raw_action, (list, tuple)):
        fit_mode = str(raw_action[1]) if len(raw_action) > 1 else None
        target_page = _page_number_for_ref(reader, raw_action[0]) if raw_action else None
        details.update(
            {
                "kind": "destination",
                "risk": "low",
                "target_page": target_page,
                "fit_mode": fit_mode,
                "summary": f"Opens to page {target_page or 'unknown'} with view mode {fit_mode or 'default'}; this controls initial view only.",
            }
        )
        return details

    if isinstance(raw_action, dict):
        action_type = str(raw_action.get("/S", "unknown"))
        details["kind"] = "action"
        details["action_type"] = action_type
        if action_type in HIGH_RISK_ACTION_TYPES:
            details["risk"] = "high"
        elif action_type in MEDIUM_RISK_ACTION_TYPES:
            details["risk"] = "medium"
        else:
            details["risk"] = "low"
        extra = []
        for key in ("/URI", "/JS", "/F", "/D"):
            if key in raw_action:
                extra.append(f"{key}={_open_action_value(raw_action[key], reader)}")
        details["summary"] = f"Runs OpenAction dictionary with action type {action_type}" + (f" ({'; '.join(extra)})" if extra else ".")
        return details

    details.update({"kind": "unknown", "risk": "medium", "summary": f"OpenAction is present but could not be fully classified: {serialized}"})
    return details


def _open_action_details(path: str) -> dict[str, Any]:
    try:
        from pypdf import PdfReader  # type: ignore[import-not-found]
    except Exception as exc:
        return {"present": None, "available": False, "error": f"pypdf unavailable: {exc}"}

    try:
        reader = PdfReader(path)
        root = reader.trailer.get("/Root", {})
        raw_action = root.get("/OpenAction")
        if raw_action is None:
            return {"present": False, "available": True}
        details = _describe_open_action(raw_action, reader)
        details["available"] = True
        return details
    except Exception as exc:
        return {"present": None, "available": True, "error": str(exc)}


def _object_ref(value: Any) -> str | None:
    ref = getattr(value, "indirect_reference", None) or getattr(value, "indirectRef", None)
    if ref is None and value.__class__.__name__ == "IndirectObject":
        ref = value
    if ref is not None and getattr(ref, "idnum", None) is not None:
        return f"{ref.idnum} {ref.generation} R"
    return None


def _resolve_pdf_object(value: Any) -> Any:
    if hasattr(value, "get_object") and value.__class__.__name__ == "IndirectObject":
        return value.get_object()
    return value


def _action_risk(action_type: str) -> str:
    if action_type in HIGH_RISK_ACTION_TYPES:
        return "high"
    if action_type in MEDIUM_RISK_ACTION_TYPES:
        return "medium"
    return "low"


def _describe_action_value(action: Any, reader: Any) -> dict[str, Any]:
    raw_action = _resolve_pdf_object(action)
    serialized = _open_action_value(action, reader)
    details: dict[str, Any] = {"raw": serialized}

    if isinstance(raw_action, (list, tuple)):
        fit_mode = str(raw_action[1]) if len(raw_action) > 1 else None
        target_page = _page_number_for_ref(reader, raw_action[0]) if raw_action else None
        details.update(
            {
                "kind": "destination",
                "risk": "low",
                "target_page": target_page,
                "fit_mode": fit_mode,
                "summary": f"Navigates to page {target_page or 'unknown'} with view mode {fit_mode or 'default'}; this controls viewer navigation only.",
            }
        )
        return details

    if isinstance(raw_action, dict):
        action_type = str(raw_action.get("/S", "unknown"))
        details.update({"kind": "action", "action_type": action_type, "risk": _action_risk(action_type)})
        extra = []
        for key in ("/URI", "/JS", "/F", "/D", "/T"):
            if key in raw_action:
                extra.append(f"{key}={_open_action_value(raw_action[key], reader)}")
        details["summary"] = f"Runs action dictionary with action type {action_type}" + (f" ({'; '.join(extra)})" if extra else ".")
        return details

    details.update({"kind": "unknown", "risk": "medium", "summary": f"Action value could not be fully classified: {serialized}"})
    return details


def _append_additional_actions(rows: list[dict[str, Any]], owner: str, owner_ref: str | None, aa_dict: Any, reader: Any) -> None:
    resolved = _resolve_pdf_object(aa_dict)
    if not isinstance(resolved, dict):
        return
    for event_key, action in resolved.items():
        event = str(event_key)
        action_details = _describe_action_value(action, reader)
        rows.append(
            {
                "owner": owner,
                "owner_ref": owner_ref,
                "event": event,
                "event_description": ADDITIONAL_ACTION_EVENTS.get(event, "additional action event"),
                **action_details,
            }
        )


def _walk_form_fields(fields: Any) -> list[Any]:
    items: list[Any] = []
    for field in fields or []:
        resolved = _resolve_pdf_object(field)
        if not isinstance(resolved, dict):
            continue
        items.append(field)
        items.extend(_walk_form_fields(resolved.get("/Kids", [])))
    return items


def _additional_action_details(path: str) -> dict[str, Any]:
    try:
        from pypdf import PdfReader  # type: ignore[import-not-found]
    except Exception as exc:
        return {"present": None, "available": False, "error": f"pypdf unavailable: {exc}", "actions": []}

    try:
        reader = PdfReader(path)
        root = reader.trailer.get("/Root", {})
        actions: list[dict[str, Any]] = []

        if root.get("/AA") is not None:
            _append_additional_actions(actions, "catalog", _object_ref(root), root.get("/AA"), reader)

        acroform = _resolve_pdf_object(root.get("/AcroForm")) if root.get("/AcroForm") is not None else None
        if isinstance(acroform, dict):
            if acroform.get("/AA") is not None:
                _append_additional_actions(actions, "acroform", _object_ref(acroform), acroform.get("/AA"), reader)
            for index, field in enumerate(_walk_form_fields(acroform.get("/Fields", [])), start=1):
                field_obj = _resolve_pdf_object(field)
                if isinstance(field_obj, dict) and field_obj.get("/AA") is not None:
                    field_name = field_obj.get("/T") or f"field {index}"
                    _append_additional_actions(actions, f"form field {field_name}", _object_ref(field), field_obj.get("/AA"), reader)

        for page_index, page in enumerate(reader.pages, start=1):
            if page.get("/AA") is not None:
                _append_additional_actions(actions, f"page {page_index}", _object_ref(page), page.get("/AA"), reader)
            for annot_index, annot in enumerate(page.get("/Annots", []) or [], start=1):
                annot_obj = _resolve_pdf_object(annot)
                if isinstance(annot_obj, dict) and annot_obj.get("/AA") is not None:
                    subtype = annot_obj.get("/Subtype", "annotation")
                    _append_additional_actions(actions, f"page {page_index} annotation {annot_index} {subtype}", _object_ref(annot), annot_obj.get("/AA"), reader)

        risk = "low"
        if any(action.get("risk") == "high" for action in actions):
            risk = "high"
        elif any(action.get("risk") == "medium" for action in actions):
            risk = "medium"
        return {
            "present": bool(actions),
            "available": True,
            "count": len(actions),
            "risk": risk if actions else None,
            "summary": f"Decoded {len(actions)} additional action event(s)." if actions else "No decoded additional actions found.",
            "actions": actions,
        }
    except Exception as exc:
        return {"present": None, "available": True, "error": str(exc), "actions": []}


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
        open_action = _open_action_details(context.file_path)
        additional_actions = _additional_action_details(context.file_path)

        for keyword, detail in HIGH_RISK_KEYWORDS.items():
            count = keyword_counts.get(keyword, 0)
            if not count:
                continue
            if keyword == "/OpenAction":
                risk = open_action.get("risk")
                severity = Severity.high
                if risk == "low":
                    severity = Severity.low
                elif risk == "medium":
                    severity = Severity.medium
                findings.append(
                    Finding(
                        analyzer=self.key,
                        title="/OpenAction present",
                        severity=severity,
                        detail=open_action.get("summary") or detail,
                        value=open_action if open_action.get("present") is not None else count,
                    )
                )
                continue
            if keyword == "/AA":
                risk = additional_actions.get("risk")
                severity = Severity.high
                if risk == "low":
                    severity = Severity.low
                elif risk == "medium":
                    severity = Severity.medium
                findings.append(
                    Finding(
                        analyzer=self.key,
                        title="/AA additional actions present",
                        severity=severity,
                        detail=additional_actions.get("summary") or detail,
                        value=additional_actions if additional_actions.get("present") is not None else count,
                    )
                )
                continue
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
        if embedded_files:
            if not keyword_counts.get("/EmbeddedFile"):
                findings.append(
                    Finding(
                        analyzer=self.key,
                        title="Embedded files reported by PyMuPDF",
                        severity=Severity.high,
                        detail="The PDF contains embedded file entries.",
                        value=len(embedded_files),
                    )
                )
            high_risk_embedded = [item for item in embedded_files if item.get("risk") == "high"]
            medium_risk_embedded = [item for item in embedded_files if item.get("risk") == "medium"]
            if high_risk_embedded:
                findings.append(
                    Finding(
                        analyzer=self.key,
                        title="High-risk embedded payloads",
                        severity=Severity.high,
                        detail="One or more embedded files look executable or script-like.",
                        value=[item.get("name") for item in high_risk_embedded],
                    )
                )
            elif medium_risk_embedded:
                findings.append(
                    Finding(
                        analyzer=self.key,
                        title="Embedded payloads need review",
                        severity=Severity.medium,
                        detail="One or more embedded files are documents, archives, identifiable payloads, or high-entropy content.",
                        value=[item.get("name") for item in medium_risk_embedded],
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
            "open_action": open_action,
            "additional_actions": additional_actions,
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

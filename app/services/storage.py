from __future__ import annotations

import re
import uuid
from pathlib import Path

from fastapi import HTTPException, UploadFile

from app.config import MAX_UPLOAD_BYTES, UPLOAD_DIR
from app.models import UploadedFileInfo


SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def safe_filename(name: str) -> str:
    cleaned = SAFE_NAME.sub("_", Path(name).name).strip("._")
    return cleaned or "upload.bin"


async def save_upload(file: UploadFile) -> tuple[Path, UploadedFileInfo]:
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    original_name = file.filename or "upload.bin"
    stored_name = f"{uuid.uuid4().hex}_{safe_filename(original_name)}"
    destination = UPLOAD_DIR / stored_name

    total = 0
    with destination.open("wb") as output:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_UPLOAD_BYTES:
                destination.unlink(missing_ok=True)
                raise HTTPException(
                    status_code=413,
                    detail=f"Upload exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit.",
                )
            output.write(chunk)

    return destination, UploadedFileInfo(
        original_name=original_name,
        stored_name=stored_name,
        size=total,
        content_type=file.content_type,
    )

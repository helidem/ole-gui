from __future__ import annotations

from fastapi import FastAPI, File, Form, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.analyzers.registry import ANALYZERS
from app.config import STATIC_DIR
from app.models import AnalysisOptions
from app.services.analysis import analyze_file
from app.services.storage import save_upload


app = FastAPI(title="Oletools GUI", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/tools")
def tools() -> list[dict[str, str]]:
    return [
        {"key": analyzer.key, "label": analyzer.label, "description": analyzer.description}
        for analyzer in ANALYZERS.values()
    ]


@app.post("/api/analyze")
async def analyze(
    file: UploadFile = File(...),
    tools: str = Form("oleid,olevba,mraptor,objects,pdf_static"),
    zip_password: str | None = Form(None),
    office_password: str | None = Form(None),
    include_macro_source: bool = Form(True),
    include_decoded_strings: bool = Form(True),
):
    path, file_info = await save_upload(file)
    options = AnalysisOptions(
        tools=[tool.strip() for tool in tools.split(",") if tool.strip()],
        zip_password=zip_password or None,
        office_password=office_password or None,
        include_macro_source=include_macro_source,
        include_decoded_strings=include_decoded_strings,
    )
    return analyze_file(path, file_info, options)

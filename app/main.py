from __future__ import annotations

from fastapi import FastAPI, File, Form, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.analyzers.registry import ANALYZERS
from app.config import APP_VERSION, STATIC_DIR
from app.models import AnalysisOptions
from app.services.analysis import analyze_file, auto_tools_for_filename, build_bulk_response
from app.services.storage import save_upload


app = FastAPI(title="Oletools GUI", version=APP_VERSION)

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


@app.get("/api/version")
def version() -> dict[str, str]:
    return {"version": APP_VERSION}


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
    auto_tools: bool = Form(False),
    zip_password: str | None = Form(None),
    office_password: str | None = Form(None),
    include_macro_source: bool = Form(True),
    include_decoded_strings: bool = Form(True),
):
    path, file_info = await save_upload(file)
    selected_tools = auto_tools_for_filename(file_info.original_name) if auto_tools else [tool.strip() for tool in tools.split(",") if tool.strip()]
    options = AnalysisOptions(
        tools=selected_tools,
        zip_password=zip_password or None,
        office_password=office_password or None,
        include_macro_source=include_macro_source,
        include_decoded_strings=include_decoded_strings,
    )
    return analyze_file(path, file_info, options)


@app.post("/api/analyze/bulk")
async def analyze_bulk(
    files: list[UploadFile] = File(...),
    tools: str = Form("oleid,olevba,mraptor,objects,pdf_static"),
    auto_tools: bool = Form(False),
    zip_password: str | None = Form(None),
    office_password: str | None = Form(None),
    include_macro_source: bool = Form(True),
    include_decoded_strings: bool = Form(True),
):
    reports = []
    manual_tools = [tool.strip() for tool in tools.split(",") if tool.strip()]
    for upload in files:
        path, file_info = await save_upload(upload)
        selected_tools = auto_tools_for_filename(file_info.original_name) if auto_tools else manual_tools
        options = AnalysisOptions(
            tools=selected_tools,
            zip_password=zip_password or None,
            office_password=office_password or None,
            include_macro_source=include_macro_source,
            include_decoded_strings=include_decoded_strings,
        )
        reports.append(analyze_file(path, file_info, options))
    return build_bulk_response(reports)

# AGENTS.md — Oletools GUI

Guidance for AI agents working in this repository. Read this before editing code.

## Project purpose

Oletools GUI is a FastAPI single-page web app for **static malware/SOC triage of uploaded Office, RTF, and PDF documents**. It wraps `oletools`-style analyzers and a custom PDF static analyzer, then renders structured findings in the browser.

Security posture: uploaded documents are untrusted. Do not add behavior that opens documents in desktop viewers, executes embedded content, detonates samples, or extracts payloads to persistent paths unless explicitly requested and isolated.

## Repository layout

```text
app/
  main.py                    FastAPI app, routes, static mount
  config.py                  constants: paths, upload limit, timeouts, version, default tools
  models.py                  Pydantic response models and Severity enum
  analyzers/
    base.py                  Analyzer interface and AnalyzerContext
    registry.py              central analyzer registration
    cli_analyzer.py          subprocess helper for oletools CLI modules
    oleid_analyzer.py        OleID wrapper
    olevba_analyzer.py       OleVBA wrapper
    mraptor_analyzer.py      MacroRaptor wrapper
    objects_analyzer.py      oleobj/rtfobj wrapper
    pdf_static_analyzer.py   custom static PDF triage logic
  services/
    analysis.py              tool selection, per-file/bulk response assembly
    filetype.py              lightweight type detection / analyzer gating
    risk.py                  risk aggregation and summary text
    storage.py               upload sanitization and size-limited writes
static/
  index.html                 UI shell/templates
  app.js                     client-side upload, API calls, result rendering
  styles.css                 UI styling
uploads/.gitkeep             upload directory placeholder; uploaded files are runtime data
Dockerfile.kasm              Kasm workspace container build
kasm-workspace.json          Kasm workspace metadata
requirements.txt             pinned Python runtime dependencies
```

## Local setup and run

```bash
cd /home/ubuntu/ole-gui
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8081
```

Open `http://localhost:8081`.

The Kasm container uses port `8085` via `OLE_GUI_PORT`; local README examples use `8081`.

## Fast validation commands

There is no dedicated test suite in this repo right now. Before finishing Python changes, run at least:

```bash
cd /home/ubuntu/ole-gui
. .venv/bin/activate 2>/dev/null || true
python -m compileall app
python - <<'PY'
from app.main import app
from app.analyzers.registry import ANALYZERS
print(app.title, sorted(ANALYZERS))
PY
```

For frontend-only changes, at minimum load the app in a browser or review `static/app.js` for syntax issues. If a server is needed, start it with:

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8081
```

## Analyzer architecture

All analyzers implement `Analyzer.analyze(context) -> AnalyzerResult` from `app/analyzers/base.py`.

To add a new analyzer:

1. Create `app/analyzers/<name>_analyzer.py`.
2. Set stable `key`, human label, and description.
3. Return `AnalyzerResult` with:
   - `status`: `ok`, `skipped`, or `error`.
   - concise `summary`.
   - structured `findings: list[Finding]`.
   - optional `data` for tables/detail rendering.
   - optional `raw_output` for CLI output.
4. Register an instance in `app/analyzers/registry.py`.
5. Update `DEFAULT_TOOLS` in `app/config.py` if it should run by default.
6. Update `auto_tools_for_filename()` in `app/services/analysis.py` and matching client-side arrays in `static/app.js` if auto-selection changes.
7. Update README and this file if the workflow changes.

Keep analyzer keys stable because the UI and API use them.

## API contract

Important endpoints:

- `GET /` serves `static/index.html`.
- `GET /api/version` returns `{version}`.
- `GET /api/tools` returns registered analyzer metadata.
- `POST /api/analyze` analyzes one file.
- `POST /api/analyze/bulk` analyzes multiple files and is what the UI currently uses.

Response shapes are defined in `app/models.py`. If you change response data, update both backend models and `static/app.js` rendering.

## File handling and safety rules

- Uploaded files are saved by `app/services/storage.py` under `uploads/` with UUID-prefixed sanitized names.
- Max upload size is `MAX_UPLOAD_BYTES` in `app/config.py`.
- Treat every upload as hostile binary data.
- Avoid logging secrets/passwords. `zip_password` and `office_password` are user-provided analysis options.
- Do not extract embedded files to durable storage by default. Prefer in-memory inspection with hashes, magic, first bytes, and previews.
- Do not submit samples to external scanners/services without explicit user approval.
- Keep static analysis deterministic and offline.

## PDF static analyzer notes

`app/analyzers/pdf_static_analyzer.py` is a large custom analyzer. Be careful with broad refactors.

Current responsibilities include:

- PDF magic/version detection.
- hash, entropy, metadata, URI extraction.
- keyword counts with hex-obfuscated PDF name handling.
- `/OpenAction` classification: distinguish benign destination/view actions from action dictionaries.
- `/AA` additional action decoding on pages, annotations, and form fields.
- PyMuPDF embedded-file inspection in memory.
- encrypted/password-gated document handling.
- incremental update marker detection.

When changing PDF findings:

- Prefer precise evidence over generic keyword alerts.
- For `/OpenAction` and `/AA`, show action type, event/owner context, page/object reference when available, and risk classification.
- For `/ObjStm`, do **not** stop at a generic “`/ObjStm` present” notice. Show useful details such as object stream object number, byte offset, `/N`, `/First`, `/Length`, filters, stream size, and embedded object previews when safely available.
- Do not classify ordinary navigation/view actions as high risk just because an action key exists.
- Do not rely solely on raw keyword counts for verdicts when parser-level details are available.

## Office / oletools analyzer notes

- CLI-backed analyzers should use `run_module()` from `app/analyzers/cli_analyzer.py` so timeouts and Python executable selection stay consistent.
- `ANALYZER_TIMEOUT_SECONDS` is currently 45 seconds.
- PDF files should generally skip Office/OLE analyzers.
- RTF handling differs: `ObjectsAnalyzer` uses `rtfobj` for `.rtf`, otherwise `oleobj`.
- Macro analyzers use `should_run_macro_analyzers()` to avoid noisy macro findings on non-document inputs.

## Frontend notes

`static/app.js` mirrors some backend constants:

- `pdfTools`
- `officeTools`
- `allTools`
- PDF/Office extension sets
- displayed fallback app version

If backend analyzer keys or auto-selection rules change, update `static/app.js` too.

Rendering is intentionally simple vanilla JS. Escape untrusted strings with `escapeHtml()` before putting them in `innerHTML`.

## Risk model

Severity values are: `info`, `low`, `medium`, `high`, `error`.

Aggregation lives in `app/services/risk.py`. `error` currently ranks like medium. Keep summaries cautious: “no obvious malicious indicators” does **not** mean safe.

## Style preferences

- Python: type hints, small helpers, explicit structured dictionaries for analyzer `data`.
- Keep analyzer outputs JSON-serializable.
- Prefer adding focused helper functions over deeply nested logic.
- Preserve backward-compatible response fields when possible.
- Avoid sweeping formatting-only changes in `pdf_static_analyzer.py`; it is long and easier to review with targeted diffs.
- Keep UI dependency-free unless there is a strong reason to add a build step.

## Common pitfalls

- Forgetting to register a new analyzer in `registry.py`.
- Updating backend auto-selection but not frontend auto-selection.
- Returning non-serializable objects from analyzer `data` or `Finding.value`.
- Treating uploaded filename extension as authoritative; use `filetype.py` magic checks where possible.
- Letting subprocess analyzers run without timeout.
- Storing extracted embedded payloads on disk during normal analysis.
- Overstating safety. Static analysis can miss malicious behavior.

## Kasm deployment notes

`Dockerfile.kasm` builds on `kasmweb/firefox:1.18.0`, installs requirements into `/opt/ole-gui/.venv`, copies `app`, `static`, and `docker/kasm/startup.sh`, and exposes `8085`.

If runtime port/startup behavior changes, update:

- `Dockerfile.kasm`
- `docker/kasm/startup.sh`
- `kasm-workspace.json`
- README

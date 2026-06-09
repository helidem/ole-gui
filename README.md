# Oletools GUI

Version: 1.0

A modular web UI for analyzing uploaded Office/RTF/PDF documents with `oletools`-style static triage.

## What It Runs

- `oleid`: high-level OLE indicators such as macros, encryption, embedded objects, and Flash.
- `olevba`: VBA/XLM macro detection, macro extraction, suspicious keyword analysis, auto-exec detection, obfuscation indicators, and IOCs.
- `mraptor`: MacroRaptor A/W/X heuristic triage for suspicious macro behavior.
- `oleobj` / `rtfobj`: embedded object reporting for Office and RTF files.
- `PDF Static`: PDFiD/pdf-parser-inspired static triage for JavaScript, launch/open actions, embedded files, URIs, encryption, object streams, metadata, hashes, entropy, and incremental updates. OpenAction entries are decoded to show whether they are benign view destinations (page/fit mode) or higher-risk action dictionaries (JavaScript, Launch, URI, SubmitForm, remote GoTo, etc.). If PyMuPDF is installed, it also extracts embedded file bytes in-memory and reports filename, size, magic type, entropy, MD5/SHA1/SHA256, first bytes, printable preview, and risk classification directly in the UI.

The app is intentionally split into small analyzer classes under `app/analyzers`. Add a new tool by creating another `Analyzer` implementation and registering it in `app/analyzers/registry.py`.

## Run Locally

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8081
```

Open `http://localhost:8081`. Use another port if `8081` is already taken.

## Notes

Treat uploaded files as untrusted. This app analyzes documents but does not sandbox Office itself. For hostile malware samples, run it inside an isolated VM/container and avoid exposing it publicly without authentication, rate limits, and storage cleanup.

## Deploy as a Kasm Workspace

This repository includes Kasm-specific container assets so the app can run as a Workspace with the built-in Firefox desktop/noVNC session.

### 1) Build and push the workspace image

```bash
docker build -f Dockerfile.kasm -t <your-registry>/ole-gui:latest .
docker push <your-registry>/ole-gui:latest
```

### 2) Import the workspace definition in Kasm

1. Copy `kasm-workspace.json` and update:
   - `image_src` to match the image you pushed.
   - `docker_registry` if you are not using Docker Hub.
2. In Kasm Admin, add a new Workspace from JSON and paste the updated definition.

### 3) Launch and use

When the Workspace starts, the app is served inside the container on port `8081` and Firefox opens `http://127.0.0.1:8081` automatically.

#!/usr/bin/env bash
set -ex # Added -x for better debugging in logs

VENV_PATH="${VENV_PATH:-/opt/ole-gui/.venv}"
OLE_GUI_PORT="${OLE_GUI_PORT:-8081}"

# 1. Start the Oletools GUI API in the background
# We use the absolute path to the venv to ensure it finds the right libraries
"${VENV_PATH}/bin/uvicorn" app.main:app --host 0.0.0.0 --port "${OLE_GUI_PORT}" --proxy-headers &

# 2. Wait for the API to be ready before opening Firefox
# This prevents Firefox from showing a "Connection Refused" error on first load
timeout 30s bash -c "until curl -s localhost:${OLE_GUI_PORT} > /dev/null; do sleep 1; done"

# 3. Open the app in Firefox
# We don't need to background this in a subshell with wait -n 
firefox --new-window "http://127.0.0.1:${OLE_GUI_PORT}" &

# 4. CRITICAL: Hand control back to the Kasm VNC startup process
# This is what keeps the desktop session alive and prevents the "Unknown Service" loop
/dockerstartup/vnc_startup.sh

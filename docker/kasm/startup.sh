#!/usr/bin/env bash
set -ex

# Use a port that doesn't conflict with Kasm internals (8081 is often taken)
export OLE_GUI_PORT=8085
VENV_PATH="/opt/ole-gui/.venv"

# 1. Start the API in the background. 
# If your app is Flask, use the python command. If FastAPI, use uvicorn.
# We use & to ensure it runs in the background.
$VENV_PATH/bin/python3 -m uvicorn app.main:app --host 0.0.0.0 --port $OLE_GUI_PORT --proxy-headers &

# 2. Wait for the server to be ready
timeout 15s bash -c "until curl -s localhost:$OLE_GUI_PORT > /dev/null; do sleep 1; done" || echo "Server taking a while..."

# 3. Launch Firefox with the sandbox disabled.
# We point to 127.0.0.1 so it stays inside the container's network.
firefox --no-sandbox --new-window "http://127.0.0.1:$OLE_GUI_PORT" &

# 4. DO NOT call vnc_startup.sh here. 
# Just exit. Kasm's parent process will keep the container alive.
exit 0

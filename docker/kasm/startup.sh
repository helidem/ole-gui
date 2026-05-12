#!/usr/bin/env bash
set -ex

# Start the API in the background
/opt/ole-gui/.venv/bin/python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8085 --proxy-headers &

# Wait for the API to be alive
timeout 15s bash -c "until curl -s localhost:8085 > /dev/null; do sleep 1; done"

# Launch Firefox (MUST have --no-sandbox)
firefox --no-sandbox --new-window "http://127.0.0.1:8085" &

# Exit and let Kasm take over
exit 0

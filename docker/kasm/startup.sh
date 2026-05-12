#!/usr/bin/env bash
set -euo pipefail

VENV_PATH="${VENV_PATH:-/opt/ole-gui/.venv}"
OLE_GUI_PORT="${OLE_GUI_PORT:-8081}"

# Start the default Kasm desktop services.
/usr/bin/start-custom.sh "$@" &

# Start the Oletools GUI API.
"${VENV_PATH}/bin/uvicorn" app.main:app --host 0.0.0.0 --port "${OLE_GUI_PORT}" --proxy-headers &

wait -n

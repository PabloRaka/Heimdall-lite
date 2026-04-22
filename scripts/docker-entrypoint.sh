#!/usr/bin/env sh
set -eu

mkdir -p /app/data /app/logs

if [ "${HEIMDALL_HOST_DEFENSE:-0}" = "1" ]; then
  if [ ! -d "${HEIMDALL_HOST_ROOT:-/host}/etc" ]; then
    echo "[entrypoint] host-defense mode enabled but host root is not mounted at ${HEIMDALL_HOST_ROOT:-/host}" >&2
    exit 1
  fi

  if ! command -v nsenter >/dev/null 2>&1; then
    echo "[entrypoint] host-defense mode requires nsenter inside the image" >&2
    exit 1
  fi
fi

python /app/scripts/init_db.py

touch /app/logs/auth.log /app/logs/access.log

exec python /app/main.py "$@"

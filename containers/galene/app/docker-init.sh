#!/bin/sh
set -e

# first arg not empty and is not `-f` or `--some-option`
if [ -n "$1" -a "${1#-}" = "$1" ]; then
  exec "$@"
fi

export GALENE_PATH="/opt/galene"

echo "[+] docker-init.sh for galene"
echo "  - Galène directory: ${GALENE_PATH}"

# Execute all scripts in /docker-init.d/
for file in /docker-init.d/*; do
  if [ -x "${file}" ]; then
    "${file}" "$@"
  elif [ -f "${file}" ]; then
    source "${file}" "$@"
  else
    echo "!!! cannot execute ${file}"
    exit 1
  fi
done

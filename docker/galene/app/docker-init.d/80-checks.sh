#!/bin/sh

echo "[+] Checking ..."

cd ${GALENE_PATH}

for d in "${GALENE_DATA}" "${GALENE_GROUPS}" "${GALENE_RECORDINGS}" "${GALENE_STATIC}"; do
      if [ -n "$d" ]; then
            if [ ! -d $d ]; then
                  echo "!!! $d -- directory not found - exiting" > /dev/stderr
                  exit 1
            fi
      fi
done

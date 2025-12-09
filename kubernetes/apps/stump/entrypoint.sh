#!/usr/bin/env sh

PUID=${PUID:-0}
PGID=${PGID:-0}

USER=stump
GROUP=stump

if ! grep -q "^${GROUP}:" /etc/group; then
    addgroup -g "$PGID" "$GROUP"
fi

if ! grep -q "^${USER}:" /etc/passwd; then
    adduser -u "$PUID" -G "$GROUP" -D -H "$USER"
fi

[ -d /config ] && chown -R "$PUID":"$PGID" /config
[ -d /data ] && chown "$PUID":"$PGID" /data

cd /app

if [ "$PUID" -eq 0 ]; then
    exec /app/stump
else
    exec su "$USER" -s /app/stump --
fi

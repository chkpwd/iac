#!/usr/bin/env bash

PORT=${PORT:-8000}
UV_CACHE_DIR=/.cache

cd /app
uv run alembic upgrade head
uv run fastapi run /app/media_manager/main.py --port "$PORT" --proxy-headers

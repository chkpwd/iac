#!/usr/bin/env sh
set -e

[ -z "$AA_BASE_URL" ] && echo "ERROR: AA_BASE_URL is required but not set" && exit 1

PUID="${PUID:-1000}"
PGID="${PGID:-100}"

export PORT="${PORT:-8286}"
export HOST="${HOST:-0.0.0.0}"
export NODE_ENV="${NODE_ENV:-production}"
export DB_PATH="${DB_PATH:-/app/data/database.db}"
export CRAWLEE_STORAGE_DIR="${CRAWLEE_STORAGE_DIR:-/app/.crawlee}"
export DOWNLOAD_FOLDER="${DOWNLOAD_FOLDER:-/app/downloads}"
export INGEST_FOLDER="${INGEST_FOLDER:-/app/ingest}"

echo "Setting up directories..."
mkdir -p /app/data /app/downloads /app/ingest /app/.crawlee

# Ensure ownership of internal working dir; external mounts rely on fsGroup
chown -R "$(id -u):$(id -g)" /app/.crawlee || true

echo "Running database migrations..."
cd /app/packages/api
node dist/db/migrate.js || echo "Warning: Migrations may have failed, continuing anyway..."

cd /app/packages/api
echo "Starting server on port $PORT..."
echo "Application will be available at http://localhost:$PORT"
echo "==================================="

exec node dist/index.js

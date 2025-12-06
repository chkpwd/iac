#!/usr/bin/env bash

exec \
    /app/readarr/bin/Readarr \
        --nobrowser \
        --data=/config \
        "$@"

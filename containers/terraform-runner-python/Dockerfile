FROM python:3.14-slim-bookworm AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1

WORKDIR /src

FROM base AS builder

ENV PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100 \
    POETRY_NO_INTERACTION=1 \
    POETRY_VERSION=1.8

RUN pip install "poetry==$POETRY_VERSION"

COPY poetry.lock pyproject.toml .

RUN poetry config virtualenvs.in-project true && \
    poetry install --only=main

FROM docker.io/library/alpine:3.23 AS opentofu

ARG VERSION="v1.9.0"

RUN \
    apk add --no-cache \
        bash \
        curl \
    && curl -fsSL -o /tmp/tofu_${VERSION}_linux_amd64.tar.gz "https://github.com/opentofu/opentofu/releases/download/${VERSION}/tofu_${VERSION//v/}_linux_amd64.tar.gz" \
    && tar -xzvf /tmp/tofu_${VERSION}_linux_amd64.tar.gz -C /tmp \
    && chmod +x /tmp/tofu

FROM ghcr.io/flux-iac/tf-runner:v0.16.0-rc.5 AS runner

USER root

COPY --from=builder --chown=65532:65532 /src/.venv /src/.venv
COPY --from=opentofu --chown=65532:65532 /tmp/tofu /usr/local/bin/terraform

ENV PATH="/src/.venv/bin:$PATH"

USER 65532:65532

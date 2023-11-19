ARG DIR=/go/src/galene
ARG VERSION=0.7.2
ARG WAIT_VERSION=2.9.0
ARG TARGET_DIR=/opt/galene

FROM golang:alpine AS builder
ARG DIR
ARG VERSION

RUN apk --no-cache add git \
    && git clone --depth 1 --branch galene-$VERSION https://github.com/jech/galene.git ${DIR}

WORKDIR ${DIR}
RUN CGO_ENABLED=0 go build -ldflags='-s -w'

FROM alpine
ARG DIR
ARG VERSION
ARG VCS_REF=$SOURCE_COMMIT
ARG TARGET_DIR
ARG WAIT_VERSION
ARG WAIT_BIN=/docker-init.d/01-docker-compose-wait

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

RUN mkdir -p ${TARGET_DIR}/groups/ \
    && chown -R appuser:appgroup ${TARGET_DIR}

LABEL maintainer="galene@flexoft.net" \
      org.label-schema.schema-version="1.0" \
      org.label-schema.name="galene" \
      org.label-schema.description="Docker image for the Galène videoconference server" \
      org.label-schema.url="http://galena.org/" \
      org.label-schema.vcs-url="https://github.com/deburau/galene" \
      org.label-schema.vendor="jech" \
      org.label-schema.version="${VERSION}" \
      org.label-schema.docker.cmd="docker run -it -p 8443:8443 deburau/galene:latest -turn ''"

EXPOSE 8443
EXPOSE 1194/tcp
EXPOSE 1194/udp

COPY --from=builder ${DIR}/LICENCE ${TARGET_DIR}/
COPY --from=builder ${DIR}/galene ${TARGET_DIR}/
COPY --from=builder ${DIR}/static/ ${TARGET_DIR}/static/
COPY app/ /

ADD https://github.com/ufoscout/docker-compose-wait/releases/download/${WAIT_VERSION}/wait ${WAIT_BIN}
RUN chmod 0755 ${WAIT_BIN}

USER appuser

WORKDIR ${TARGET_DIR}

ENTRYPOINT ["/docker-init.sh"]

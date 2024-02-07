FROM golang:1.22-alpine AS build

RUN apk add --no-cache git upx

RUN git clone https://github.com/oxide-one/systemd.go /systemd.go

ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

WORKDIR /systemd.go
RUN go mod download && \
    go build -ldflags="-w -s" -a -o /build/systemd.go cmd/systemd-go/systemd.go

RUN upx /build/systemd.go

FROM alpine

ENV GOSU_VERSION 1.17

RUN set -eux; \
    apk add --no-cache --virtual .gosu-deps \
        ca-certificates \
        dpkg \
        gnupg \
    ; \
    dpkgArch="$(dpkg --print-architecture | awk -F- '{ print $NF }')"; \
    wget -O /usr/local/bin/gosu "https://github.com/tianon/gosu/releases/download/$GOSU_VERSION/gosu-$dpkgArch"; \
    wget -O /usr/local/bin/gosu.asc "https://github.com/tianon/gosu/releases/download/$GOSU_VERSION/gosu-$dpkgArch.asc"; \
    \
    # verify the signature
    export GNUPGHOME="$(mktemp -d)"; \
    gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys B42F6819007F00F88E364FD4036A9C25BF357DD4; \
    gpg --batch --verify /usr/local/bin/gosu.asc /usr/local/bin/gosu; \
    gpgconf --kill all; \
    rm -rf "$GNUPGHOME" /usr/local/bin/gosu.asc; \
    \
    # clean up fetch dependencies
    apk del --no-network .gosu-deps; \
    \
    chmod +x /usr/local/bin/gosu; \
    # verify that the binary works
    gosu --version; \
    gosu nobody true

COPY --from=build /build/systemd.go /bin/systemd.go

RUN apk add --no-cache zsh fzf ncurses sl fortune && \
    adduser -s /bin/zsh -D dev && \
    rm /bin/dd /bin/cp /usr/bin/md5sum /usr/bin/xargs

COPY entrypoint.sh /var/opt/entry.sh
COPY printout /home/dev/printout

RUN chmod +x /var/opt/entry.sh && \
    chown -R dev:dev /home/dev && \
    sed -i -e 's/^root::/root:!:/' /etc/shadow

#USER dev

#ENTRYPOINT ["gosu", "dev", "/var/opt/entry.sh"]

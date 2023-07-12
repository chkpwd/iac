FROM nginx:1.13.3

RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && \
    apt-get install -y iputils-ping procps openssl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /etc/nginx/

COPY proxy/ssl.conf /etc/ssl/openssl.cnf

RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -config /etc/ssl/openssl.cnf -extensions v3_ca \
    -keyout cert.key -out cert.crt

COPY proxy/default.conf /etc/nginx/conf.d/default.conf

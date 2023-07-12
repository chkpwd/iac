FROM quay.io/ansible/ubuntu2204-test-container:main
# ubuntu2204 comes with mysql-client-8

# iproute2  # To grab docker network gateway address
RUN apt-get update -y && \
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y --no-install-recommends && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    python3.10 \
    mysql-client \
    iproute2

RUN python3.10 -m pip install --disable-pip-version-check --no-cache-dir pymysql==1.0.2

ENV container=docker
CMD ["/sbin/init"]

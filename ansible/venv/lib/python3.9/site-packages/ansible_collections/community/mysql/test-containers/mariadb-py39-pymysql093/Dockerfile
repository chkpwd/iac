FROM quay.io/ansible/ubuntu2004-test-container:main
# ubuntu2004 comes with mariadb-client-10.3

# iproute2                     # To grab docker network gateway address
RUN apt-get update -y && \
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y --no-install-recommends && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    python3.9 \
    mariadb-client \
    iproute2

RUN python3.9 -m pip install --disable-pip-version-check --no-cache-dir pymysql==0.9.3

ENV container=docker
CMD ["/sbin/init"]

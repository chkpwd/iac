FROM quay.io/ansible/ubuntu2004-test-container:main
# ubuntu2004 comes with mysql-client-8

# iproute2  # To grab docker network gateway address
RUN apt-get update -y && \
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y --no-install-recommends && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    python3.9 \
    mysql-client \
    iproute2

# cffi      # To connect to MySQL 8 with Python3.9 and PyMySQL
RUN python3.9 -m pip install --disable-pip-version-check --no-cache-dir cffi pymysql==0.9.3

ENV container=docker
CMD ["/sbin/init"]

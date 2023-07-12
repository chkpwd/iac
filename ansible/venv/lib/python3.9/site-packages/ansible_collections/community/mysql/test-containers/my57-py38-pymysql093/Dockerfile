FROM quay.io/ansible/ubuntu1804-test-container:main
# ubuntu1804 comes with mysql-client-5.7

# iproute2  # To grab docker network gateway address
RUN apt-get update -y && \
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y --no-install-recommends && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    python3.8 \
    mysql-client \
    iproute2

RUN python3.8 -m pip install --disable-pip-version-check --no-cache-dir pymysql==0.9.3

ENV container=docker
CMD ["/sbin/init"]

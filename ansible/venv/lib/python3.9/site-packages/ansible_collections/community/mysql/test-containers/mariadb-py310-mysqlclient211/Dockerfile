FROM quay.io/ansible/ubuntu2204-test-container:main
# ubuntu2204 comes with mariadb-client-10.6

# iproute2                     # To grab docker network gateway address
# python3.10-dev               # Reqs for mysqlclient
# default-libmysqlclient-dev   # Reqs for mysqlclient
# build-essential              # Reqs for mysqlclient
RUN apt-get update -y && \
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y --no-install-recommends && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    python3.10 \
    python3.10-dev \
    mariadb-client \
    iproute2 \
    default-libmysqlclient-dev \
    build-essential

RUN python3.10 -m pip install --disable-pip-version-check --no-cache-dir mysqlclient==2.1.1 

ENV container=docker
CMD ["/sbin/init"]

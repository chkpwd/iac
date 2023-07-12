FROM quay.io/ansible/ubuntu2004-test-container:main
# ubuntu2004 comes with mariadb-client-10.3

# iproute2                     # To grab docker network gateway address
# python3.9-dev                # Reqs for mysqlclient
# default-libmysqlclient-dev   # Reqs for mysqlclient
# build-essential              # Reqs for mysqlclient
RUN apt-get update -y && \
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y --no-install-recommends && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    python3.9 \
    python3.9-dev \
    mariadb-client \
    iproute2 \
    default-libmysqlclient-dev \
    build-essential

RUN python3.9 -m pip install --disable-pip-version-check --no-cache-dir mysqlclient==2.0.3 

ENV container=docker
CMD ["/sbin/init"]

FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /cyberark

# install python 3
RUN apt-get update && \
    apt-get install -y python3-pip && \
    pip3 install --upgrade pip

ARG ANSIBLE_VERSION
# install ansible and its test tool
RUN pip3 install ansible==${ANSIBLE_VERSION}.* pytest-testinfra

# install docker installation requirements
RUN apt-get update && \
    apt-get install -y apt-transport-https \
                       ca-certificates \
                       curl \
                       software-properties-common

# install docker
RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
RUN add-apt-repository \
       "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
       $(lsb_release -cs) \
       stable"

RUN apt-get update && \
    apt-get -y install docker-ce

# NOTE: Everything above is copied from REPO_ROOT/tests/conjur_variable/Dockerfile. It defines a
# standard container image for running ansible tests

# install ruby
RUN apt-get update && apt-get install -y gcc build-essential
RUN apt-add-repository -y ppa:brightbox/ruby-ng && apt-get update && apt-get install -y ruby2.7 ruby2.7-dev
RUN gem install conjur-cli
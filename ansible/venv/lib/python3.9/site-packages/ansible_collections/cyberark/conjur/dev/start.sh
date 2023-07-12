#!/bin/bash
set -ex


declare -x ANSIBLE_CONJUR_AUTHN_API_KEY=''
declare -x CLI_CONJUR_AUTHN_API_KEY=''
declare cli_cid=''
declare conjur_cid=''
declare ansible_cid=''
# normalises project name by filtering non alphanumeric characters and transforming to lowercase
declare -x COMPOSE_PROJECT_NAME

COMPOSE_PROJECT_NAME=$(echo "${BUILD_TAG:-ansible-pluging-testing}-conjur-host-identity" | sed -e 's/[^[:alnum:]]//g' | tr '[:upper:]' '[:lower:]')
export COMPOSE_PROJECT_NAME

# get conjur client auth api key
function api_key_for {
  local role_id=$1
  if [ -n "$role_id" ]
  then
    docker exec "${conjur_cid}" rails r "print Credentials['${role_id}'].api_key"
  else
    echo ERROR: api_key_for called with no argument 1>&2
    exit 1
  fi
}

function hf_token {
  docker exec "${cli_cid}" bash -c 'conjur hostfactory tokens create --duration-days=5 ansible/ansible-factory | jq -r ".[0].token"'
}

function setup_conjur {
  echo "---- setting up conjur ----"
  # run policy
  docker exec "${cli_cid}" conjur policy load root /policy/root.yml
  # set secret values
  docker exec "${cli_cid}" bash -ec 'conjur variable values add ansible/target-password target_secret_password'
}

function setup_conjur_identities {
  echo "---scale up inventory nodes and setup the conjur identity there---"
  teardown_and_setup
  docker exec "${ansible_cid}" env HFTOKEN="$(hf_token)" bash -ec "
    cd dev
    ansible-playbook playbooks/conjur-identity-setup/conjur_role_playbook.yml"
}

 # Scale up inventory nodes
function teardown_and_setup {
  docker-compose up -d --force-recreate --scale test_app_ubuntu=2 test_app_ubuntu
  docker-compose up -d --force-recreate --scale test_app_centos=2 test_app_centos
}

function wait_for_server {
  # shellcheck disable=SC2016
  docker exec "${cli_cid}" bash -ec '
    for i in $( seq 20 ); do
      curl -o /dev/null -fs -X OPTIONS ${CONJUR_APPLIANCE_URL} > /dev/null && echo "server is up" && break
      echo "."
      sleep 2
    done
  '
}

function fetch_ssl_cert {
  (docker-compose exec -T conjur-proxy-nginx cat cert.crt) > conjur.pem
}

function generate_inventory {
  # Use a different inventory file for docker-compose v1 and v2 or later
  playbook_file="inventory-playbook-v2.yml"
  compose_ver=$(docker-compose version --short)
  if [[ $compose_ver == "1"* ]]; then
    playbook_file="inventory-playbook.yml"
  fi

  # uses .j2 template to generate inventory prepended with COMPOSE_PROJECT_NAME
  docker-compose exec -T ansible bash -ec "
    cd dev
    ansible-playbook playbooks/inventory-setup/$playbook_file
  "
}

function clean {
   echo 'Removing dev environment'
   echo '---'
   docker-compose down -v
   rm -rf inventory.tmp
}

function main() {
  clean
  docker-compose up -d --build
  generate_inventory

  conjur_cid=$(docker-compose ps -q conjur)
  cli_cid=$(docker-compose ps -q conjur_cli)
  fetch_ssl_cert
  wait_for_server

  CLI_CONJUR_AUTHN_API_KEY=$(api_key_for 'cucumber:user:admin')
  docker-compose up -d conjur_cli

  cli_cid=$(docker-compose ps -q conjur_cli)
  setup_conjur

  ANSIBLE_CONJUR_AUTHN_API_KEY=$(api_key_for 'cucumber:host:ansible/ansible-master')
  docker-compose up -d ansible

  ansible_cid=$(docker-compose ps -q ansible)
  setup_conjur_identities
}
  main
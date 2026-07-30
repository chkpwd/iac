timeout := "300s"

default:
  just --list

init:
  ansible-galaxy install -r requirements.yml
  ansible-galaxy collection install -r requirements.yml

switch host="mk-sw-01":
  ansible-playbook playbooks/infra/switch-config.yml --limit {{host}}

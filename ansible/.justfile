timeout := "300s"

# List tasks
default:
  just --list

# Bootstrap Galaxy roles
init:
  ansible-galaxy install -r requirements.yml
  ansible-galaxy collection install -r requirements.yml

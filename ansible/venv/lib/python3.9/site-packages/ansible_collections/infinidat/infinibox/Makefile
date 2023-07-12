# Copyright: (c) 2022, Infinidat <info@infinidat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# vim: set foldmethod=indent foldnestmax=1 foldcolumn=1:

# A Makefile for creating, running and testing Infindat's Ansible collection.

### Dependencies ###
# - jq: https://stedolan.github.io/jq/
# - spruce: https://github.com/geofffranks/spruce

### environment ###
# Include an env file with secrets.  This exposes the secrets
# as envvars only for the life of make.  It does not
# pollute the environment persistently.
# Format:
# API_KEY=someAnsibleGalaxyApiKey
# The key only needs to be valid to use target galaxy-colletion-publish.

_env = ~/.ssh/ansible-galaxy.sh
include $(_env)
export $(shell sed 's/=.*//' $(_env))

# Use color in Makefiles.
_use_color = true

include Makefile-help

### Vars ###
_version            	= $(shell spruce json galaxy.yml | jq '.version'   | sed 's?"??g')
_namespace          	= $(shell spruce json galaxy.yml | jq '.namespace' | sed 's?"??g')
_name               	= $(shell spruce json galaxy.yml | jq '.name'      | sed 's?"??g')
_install_path       	= ~/.ansible/collections
_install_path_local 	= $$HOME/.ansible/collections
_python_version     	= python3.8
_venv               	= venv
_requirements-file  	= requirements.txt
_requirements-dev-file  = requirements-dev.txt
_user               	= psus-gitlab-cicd
_password_file      	= vault_password
_password           	= $$(cat vault_password.txt)
_ibox_url           	= ibox1521
_infinishell_creds  	= --user $(_user) --password $(_password) $(_ibox_url)
SHELL               	= /bin/bash
_ansible_clone      	= ~/cloud/ansible
_network_space_ips  	= 172.31.32.145 172.31.32.146 172.31.32.147 172.31.32.148 172.31.32.149 172.31.32.150
_modules                = "infini_cluster.py" "infini_export.py" "infini_host.py" "infini_network_space.py" "infini_port.py" "infini_vol.py" "infini_export_client.py" "infini_fs.py" "infini_map.py" "infini_pool.py" "infini_user.py"

##@ General
create-venv: ## Setup venv.
	$(_python_version) -m venv $(_venv) && \
	source $(_venv)/bin/activate && \
	python -m pip install --upgrade pip && \
	python -m pip install --upgrade --requirement $(_requirements-file)
	python -m pip install --upgrade --requirement $(_requirements-dev-file)

_check-vars:
ifeq ($(strip $(API_KEY)),)
	@echo "API_KEY variable is unset" && false
endif

env-show: _check-vars
	@echo "API_KEY=[ set but redacted ]"

version: _check-vars  ## Show versions.
	@echo -e $(_begin)
	ansible --version
	@echo
	ansible-galaxy collection list
	@echo -e $(_finish)

_test-venv:
	@# Test that a venv is activated
ifndef VIRTUAL_ENV
	@echo "Error: Virtual environment not set"
	@echo -e "\nRun:\n  make pyvenv"
	@echo -e "  source $(_venv)/bin/activate\n"
	exit 1
endif
	@echo "Virtual environment set"

pylint:
	@echo -e $(_begin)
	cd plugins/modules && \
		pylint infini_network_space.py
	cd -
	@echo -e $(_finish)

pyfind:  ## Search project python files using: f='search term' make pyfind
	find . -name "*.py" | xargs grep -n "$$f" | egrep -v 'venv|eggs|parts|\.git|external-projects|build'

##@ Galaxy

galaxy-collection-build:  ## Build the collection.
	@echo -e $(_begin)
	rm -rf collections/
	ansible-galaxy collection build
	@echo -e $(_finish)

galaxy-collection-build-force: ## Force build the collection. Overwrite an existing collection file.
	@echo -e $(_begin)
	ansible-galaxy collection build --force
	@echo -e $(_finish)

galaxy-collection-publish: _check-vars  ## Publish the collection to https://galaxy.ansible.com/ using the API key provided.
	@echo -e $(_begin)
	ansible-galaxy collection publish --api-key $(API_KEY) ./$(_namespace)-$(_name)-$(_version).tar.gz -vvv
	@echo -e $(_finish)

galaxy-collection-install:  ## Download and install from galaxy.ansible.com. This will wipe $(_install_path).
	@echo -e $(_begin)
	ansible-galaxy collection install $(_namespace).$(_name) --collections-path $(_install_path) --force
	@echo -e $(_finish)

galaxy-collection-install-locally:  ## Download and install from local tar file.
	@echo -e $(_begin)
	ansible-galaxy collection install --force $(_namespace)-$(_name)-$(_version).tar.gz --collections-path $(_install_path_local)
	@echo -e $(_finish)

##@ Playbooks Testing
_test_playbook:
	@# Run a playbook specified by an envvar.
	@# See DEV_README.md
	@# vault_pass env var must be exported.
	cd playbooks && \
		export ANSIBLE_LIBRARY=/home/dohlemacher/cloud/ansible-infinidat-collection/playbooks/plugins/modules; \
		export ANSIBLE_MODULE_UTILS=/home/dohlemacher/cloud/ansible-infinidat-collection/plugins/module_utils; \
		if [ ! -e "../vault_password.txt" ]; then \
			echo "Please add your vault password to vault_password.txt"; \
			exit 1; \
		fi; \
		ansible-playbook \
			$$ask_become_pass \
			--inventory "inventory" \
			--extra-vars "@../ibox_vars/iboxCICD.yaml" \
			--vault-password-file ../vault_password.txt \
			"$$playbook_name"; \
	cd -

test-create-resources:  ## Run full creation test suite as run by Gitlab CICD.
	@echo -e $(_begin)
	ask_become_pass="-K" playbook_name=test_create_resources.yml $(_make) _test_playbook
	@echo -e $(_finish)

test-remove-resources:  ## Run full removal  test suite as run by Gitlab CICD.
	@echo -e $(_begin)
	ask_become_pass="-K" playbook_name=test_remove_resources.yml $(_make) _test_playbook
	@echo -e $(_finish)

test-create-snapshots:  ## Test creating immutable snapshots.
	@echo -e $(_begin)
	playbook_name=test_create_snapshots.yml $(_make) _test_playbook
	@echo -e $(_finish)

test-remove-snapshots:  ## Test removing immutable snapshots (teardown).
	@echo -e $(_begin)
	playbook_name=test_remove_snapshots.yml $(_make) _test_playbook
	@echo -e $(_finish)

test-create-net-spaces: dev-install-modules-to-local-collection  ## Test creating network spaces.
	@echo -e $(_begin)
	playbook_name=test_create_network_spaces.yml $(_make) _test_playbook
	@echo -e $(_finish)

test-remove-net-spaces:  ## Test removing net spaces (teardown).
	@echo -e $(_begin)
	playbook_name=test_remove_network_spaces.yml $(_make) _test_playbook
	@echo -e $(_finish)

test-create-map-cluster:  ## Run full creation test suite as run by Gitlab CICD.
	@echo -e $(_begin)
	playbook_name=test_create_map_cluster.yml $(_make) _test_playbook
	@echo -e $(_finish)

test-remove-map-cluster:  ## Run full removal  test suite as run by Gitlab CICD.
	@echo -e $(_begin)
	playbook_name=test_remove_map_cluster.yml $(_make) _test_playbook
	@echo -e $(_finish)

##@ Infinisafe Demo

infinisafe-demo-setup:  ## Setup infinisafe demo.
	@echo -e $(_begin)
	playbook_name=infinisafe_demo_setup.yml $(_make) _test_playbook
	@echo -e $(_finish)

infinisafe-demo-runtest:  ## Run tests on infinisafe demo snapshot on forensics host.
	@echo -e $(_begin)
	ask_become_pass="-K" playbook_name=infinisafe_demo_runtest.yml $(_make) _test_playbook
	@echo -e $(_finish)

infinisafe-demo-teardown:  ## Teardown infinisafe demo.
	@echo -e $(_begin)
	ask_become_pass="-K" playbook_name=infinisafe_demo_teardown.yml $(_make) _test_playbook
	@echo -e $(_finish)

##@ Hacking
#_module_under_test = infini_network_space
_module_under_test = infini_fs

dev-hack-create-links:  ## Create soft links inside an Ansible clone to allow module hacking.
	@#echo "Creating hacking module links"
	@for m in $(_modules); do \
		ln --force --symbolic $$(pwd)/plugins/modules/$$m $(_ansible_clone)/lib/ansible/modules/infi/$$m; \
	done
	@#echo "Creating hacking module_utils links $(_module_utilities)"
	@for m in "infinibox.py" "iboxbase.py"; do \
		ln --force --symbolic $$(pwd)/plugins/module_utils//$$m $(_ansible_clone)/lib/ansible/module_utils/$$m; \
	done

_dev-hack-module: dev-hack-create-links  # Run module. PDB is available using breakpoint().
	cwd=$$(pwd) && \
	cd $(_ansible_clone) && \
		JSON_IN="$$cwd/tests/hacking/$(_module_under_test)_$${state}.json" && \
		if [[ ! -a "$$JSON_IN" ]]; then \
			>&2 echo "Error: $$JSON_IN not found"; \
			exit; \
		fi; \
		source venv/bin/activate 1> /dev/null 2> /dev/null && \
		source hacking/env-setup 1> /dev/null 2> /dev/null && \
		AIC=/home/dohlemacher/cloud/ansible-infinidat-collection \
		ANS=/home/dohlemacher/cloud/ansible \
		PYTHONPATH="$$PYTHONPATH:$$AIC/plugins/modules" \
		PYTHONPATH="$$PYTHONPATH:$$AIC/plugins/module_utils" \
		PYTHONPATH="$$PYTHONPATH:$$ANS/lib" \
		PYTHONPATH="$$PYTHONPATH:$$ANS/hacking/build_library/build_ansible" \
		PYTHONPATH="$$PYTHONPATH:$$ANS/venv/lib/python3.8/site-packages" \
		python -m "$(_module_under_test)" "$$JSON_IN" 2>&1 | \
			grep -v 'Unverified HTTPS request'

_dev-hack-module-jq:  # If module is running to the point of returning json, use this to run it and prettyprint using jq.
	@$(_make) _dev-hack-module | egrep 'changed|failed' | jq '.'

dev-hack-module-stat:  ## Hack stat.
	@state=stat    $(_make) _dev-hack-module

dev-hack-module-stat-jq:  ## Hack stat with jq.
	@state=stat    $(_make) _dev-hack-module-jq

dev-hack-module-present:  ## Hack present.
	@state=present $(_make) _dev-hack-module

dev-hack-module-present-jq:  ## Hack present with jq.
	@state=present $(_make) _dev-hack-module-jq

dev-hack-module-absent:  ## Hack absent.
	@state=absent $(_make) _dev-hack-module

dev-hack-module-absent-jq:  ## Hack absent with jq.
	@state=absent $(_make) _dev-hack-module-jq

##@ Test Module
_module = infini_network_space.py

find-default-module-path:  ## Find module path.
	ansible-config list | spruce json | jq '.DEFAULT_MODULE_PATH.default' | sed 's?"??g'

_collection_local_path = ~/.ansible/collections/ansible_collections/infinidat/infinibox/plugins
dev-install-modules-to-local-collection:  ## Copy modules to local collection
	@echo -e $(_begin)
	@echo "local collection path: $(_collection_local_path)"
	@echo "Installing modules locally"
	@cp plugins/modules/*.py $(_collection_local_path)/modules
	@echo "Installing utilities locally"
	@cp plugins/module_utils/*.py $(_collection_local_path)/module_utils
	@echo "Installing filters locally"
	@cp plugins/filter/*.py $(_collection_local_path)/filter
	@echo -e $(_finish)

##@ ansible-test
test-sanity:  ## Run ansible sanity tests
	@# in accordance with
	@# https://docs.ansible.com/ansible/devel/dev_guide/developing_collections.html#testing-collections
	@# This runs on an collection installed from galaxy. This makes it
	@# somewhat useless for dev and debugging. Use target test-sanity-locally.
	cd $(_install_path)/ansible_collections/infinidat/infinibox && \
		ansible-test sanity --docker default -v

_setup-sanity-locally: galaxy-collection-build-force galaxy-collection-install-locally
	@# Setup a test env.
	cd $(_install_path_local)/ansible_collections/infinidat/infinibox && \
		$(_python_version) -m venv $(_venv) && \
		source $(_venv)/bin/activate && \
		python -m pip install --upgrade pip && \
		python -m pip install --upgrade --requirement $(_requirements-file)

test-sanity-locally: _setup-sanity-locally  ## Run ansible sanity tests locally.
	@# in accordance with
	@# https://docs.ansible.com/ansible/devel/dev_guide/developing_collections.html#testing-collections
	@# This runs on an collection installed locally making it useful for dev and debugging.
	cd $(_install_path_local)/ansible_collections/infinidat/infinibox && \
		ansible-test sanity --docker default --requirements $(_requirements-file)

test-sanity-locally-all: galaxy-collection-build-force galaxy-collection-install-locally test-sanity-locally  ## Run all sanity tests locally.
	@# Run local build, install and sanity test.
	@# Note that this will wipe $(_install_path_local).
	@echo "test-sanity-locally-all completed"

##@ IBox
infinishell:  ## Run infinishell.
	@TERM=xterm infinishell $(_infinishell_creds) --json

infinishell-events:  # Run infinishell with hint to watch events.
	@TERM=xterm echo "Command: event.watch username=$(_user) exclude=USER_LOGGED_OUT,USER_LOGIN_SUCCESS,USER_SESSION_EXPIRED,USER_LOGIN_FAILURE tail_length=35"
	@TERM=xterm infinishell $(_infinishell_creds)

infinishell-network-space-iscsi-create:  ## Create a network space using infinishell.
	@echo -e $(_begin)
	@TERM=xterm infinishell --cmd="config.net_space.create name=iSCSI service=iSCSI interface=PG1 network=172.31.32.0/19 -y" $(_infinishell_creds) 2>&1 \
		| egrep 'created|already exists' && \
	for ip in $(_network_space_ips); do \
		echo "Creating IP $$ip" && \
		TERM=xterm infinishell --cmd="config.net_space.ip.create net_space=iSCSI ip_address=$$ip -y" $(_infinishell_creds) 2>&1 \
			| egrep 'created|NET_SPACE_ADDRESS_CONFLICT' && \
		echo "Enabling IP $$ip"; \
	done
	@echo -e $(_finish)

infinishell-network-space-iscsi-delete:  ## Delete a network space using infinishell.
	@echo -e $(_begin)
	@for ip in $(_network_space_ips); do \
		echo "Disabling IP $$ip" && \
		TERM=xterm infinishell --cmd="config.net_space.ip.disable net_space=iSCSI ip_address=$$ip -y" $(_infinishell_creds) 2>&1 \
			| egrep 'disabled|IP_ADDRESS_ALREADY_DISABLED|no such IP address|No such network space' && \
		echo "Deleting IP $$ip" && \
		TERM=xterm infinishell --cmd="config.net_space.ip.delete  net_space=iSCSI ip_address=$$ip -y" $(_infinishell_creds) 2>&1 \
			| egrep '$$ip deleted|no such IP address|No such network space';  \
	done
	@echo
	@echo "Deleting network space iSCSI" && \
	TERM=xterm infinishell --cmd="config.net_space.delete net_space=iSCSI -y" $(_infinishell_creds) 2>&1 \
		| egrep 'deleted|No such network space';
	@echo -e $(_finish)

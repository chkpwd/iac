SHELL := /bin/bash

# To tell ansible-test and Make to not kill the containers on failure or
# end of tests. Disabled by default.
ifdef keep_containers_alive
	_keep_containers_alive = --docker-terminate never
endif

# This match what GitHub Action will do. Disabled by default.
ifdef continue_on_errors
	_continue_on_errors = --retry-on-error --continue-on-error
endif


db_ver_tuple := $(subst ., , $(db_engine_version))
db_engine_version_flat := $(word 1, $(db_ver_tuple))$(word 2, $(db_ver_tuple))

con_ver_tuple := $(subst ., , $(connector_version))
connector_version_flat := $(word 1, $(con_ver_tuple))$(word 2, $(con_ver_tuple))$(word 3, $(con_ver_tuple))

py_ver_tuple := $(subst ., , $(python))
python_version_flat := $(word 1, $(py_ver_tuple))$(word 2, $(py_ver_tuple))

ifeq ($(db_engine_version_flat), 57)
	db_client := my57
else
	db_client := $(db_engine_name)
endif


.PHONY: test-integration
test-integration:
	@echo -n $(db_engine_name) > tests/integration/db_engine_name
	@echo -n $(db_engine_version) > tests/integration/db_engine_version
	@echo -n $(connector_name) > tests/integration/connector_name
	@echo -n $(connector_version) > tests/integration/connector_version
	@echo -n $(python) > tests/integration/python
	@echo -n $(ansible) > tests/integration/ansible

	# Create podman network for systems missing it. Error can be ignored
	podman network create podman || true
	podman run \
		--detach \
		--replace \
		--name primary \
		--env MARIADB_ROOT_PASSWORD=msandbox \
		--env MYSQL_ROOT_PASSWORD=msandbox \
		--network podman \
		--publish 3307:3306 \
		--health-cmd 'mysqladmin ping -P 3306 -pmsandbox | grep alive || exit 1' \
		docker.io/library/$(db_engine_name):$(db_engine_version) \
		mysqld
	podman run \
		--detach \
		--replace \
		--name replica1 \
		--env MARIADB_ROOT_PASSWORD=msandbox \
		--env MYSQL_ROOT_PASSWORD=msandbox \
		--network podman \
		--publish 3308:3306 \
		--health-cmd 'mysqladmin ping -P 3306 -pmsandbox | grep alive || exit 1' \
		docker.io/library/$(db_engine_name):$(db_engine_version) \
		mysqld
	podman run \
		--detach \
		--replace \
		--name replica2 \
		--env MARIADB_ROOT_PASSWORD=msandbox \
		--env MYSQL_ROOT_PASSWORD=msandbox \
		--network podman \
		--publish 3309:3306 \
		--health-cmd 'mysqladmin ping -P 3306 -pmsandbox | grep alive || exit 1' \
		docker.io/library/$(db_engine_name):$(db_engine_version) \
		mysqld
	# Setup replication and restart containers
	podman exec primary bash -c 'echo -e [mysqld]\\nserver-id=1\\nlog-bin=/var/lib/mysql/primary-bin > /etc/mysql/conf.d/replication.cnf'
	podman exec replica1 bash -c 'echo -e [mysqld]\\nserver-id=2\\nlog-bin=/var/lib/mysql/replica1-bin > /etc/mysql/conf.d/replication.cnf'
	podman exec replica2 bash -c 'echo -e [mysqld]\\nserver-id=3\\nlog-bin=/var/lib/mysql/replica2-bin > /etc/mysql/conf.d/replication.cnf'
	# Don't restart a container unless it is healthy
	while ! podman healthcheck run primary && [[ "$$SECONDS" -lt 120 ]]; do sleep 1; done
	podman restart -t 30 primary
	while ! podman healthcheck run replica1 && [[ "$$SECONDS" -lt 120 ]]; do sleep 1; done
	podman restart -t 30 replica1
	while ! podman healthcheck run replica2 && [[ "$$SECONDS" -lt 120 ]]; do sleep 1; done
	podman restart -t 30 replica2
	while ! podman healthcheck run primary && [[ "$$SECONDS" -lt 120 ]]; do sleep 1; done
	mkdir -p .venv/$(ansible)
	python$(local_python_version) -m venv .venv/$(ansible)

	# Start venv (use `; \` to keep the same shell)
	source .venv/$(ansible)/bin/activate; \
	python$(local_python_version) -m ensurepip; \
	python$(local_python_version) -m pip install --disable-pip-version-check \
	https://github.com/ansible/ansible/archive/$(ansible).tar.gz; \
	set -x; \
	ansible-test integration $(target) -v --color --coverage --diff \
	--docker ghcr.io/ansible-collections/community.mysql/test-container\
	-$(db_client)-py$(python_version_flat)-$(connector_name)$(connector_version_flat):latest \
	--docker-network podman $(_continue_on_errors) $(_keep_containers_alive) --python $(python); \
	set +x
	# End of venv

	rm tests/integration/db_engine_name
	rm tests/integration/db_engine_version
	rm tests/integration/connector_name
	rm tests/integration/connector_version
	rm tests/integration/python
	rm tests/integration/ansible
ifndef keep_containers_alive
	podman stop --time 0 --ignore primary replica1 replica2
	podman rm --ignore --volumes primary replica1 replica2
endif

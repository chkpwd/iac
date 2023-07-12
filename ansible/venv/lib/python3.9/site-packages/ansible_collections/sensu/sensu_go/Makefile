# Make sure we have ansible_collections/sensu/sensu_go as a prefix. This is
# ugly as heck, but it works. I suggest all future developer to treat next few
# lines as an opportunity to learn a thing or two about GNU make ;)
collection := $(notdir $(realpath $(CURDIR)      ))
namespace  := $(notdir $(realpath $(CURDIR)/..   ))
toplevel   := $(notdir $(realpath $(CURDIR)/../..))

err_msg := Place collection at <WHATEVER>/ansible_collections/sensu/sensu_go
ifeq (true,$(CI))
  $(info Running in CI setting, skipping directory checks.)
else ifneq (sensu_go,$(collection))
  $(error $(err_msg))
else ifneq (sensu,$(namespace))
  $(error $(err_msg))
else ifneq (ansible_collections,$(toplevel))
  $(error $(err_msg))
endif

python_version := $(shell \
  python -c 'import sys; print(".".join(map(str, sys.version_info[:2])))' \
)

molecule_scenarios := $(wildcard tests/integration/molecule/*)


.PHONY: help
help:
	@echo Available targets:
	@fgrep "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sort

.PHONY: sanity
sanity:  ## Run sanity tests
	pip3 install -r sanity.requirements -r collection.requirements
	pip install pyyaml
	flake8
	if which ansible-lint 2> /dev/null; then ansible-lint -p roles/*; fi
	ansible-test sanity --docker
	python3 ./tests/sanity/validate-role-metadata.py roles/*

.PHONY: units
units:  ## Run unit tests
	pip3 install -r collection.requirements
	-ansible-test coverage erase # On first run, there is nothing to erase.
	ansible-test units --docker --coverage
	ansible-test coverage html --requirements
	ansible-test coverage report --omit 'tests/*' --show-missing

.PHONY: integration
integration:  ## Run integration tests
	pip3 install -r integration.requirements -r collection.requirements
	pytest -s --molecule-base-config=base.yml tests/integration/molecule

.PHONY: $(molecule_scenarios)
$(molecule_scenarios):
	pytest -s --molecule-base-config=base.yml $@

.PHONY: integration_ci
integration_ci:  ## Run integration tests on CircleCI
	pip3 install -r integration.requirements -r collection.requirements
	mkdir -p test_results/integration
	pytest -s \
	  --junitxml=test_results/integration/junit.xml \
	  --molecule-base-config=base.yml \
	  $$(circleci tests glob "tests/integration/molecule/*/molecule.yml" \
	     | circleci tests split --split-by=timings)

.PHONY: docs
docs:  ## Build collection documentation
	pip3 install -r docs.requirements
	$(MAKE) -C docs -f Makefile.custom docs

.PHONY: clean
clean:  ## Remove all auto-generated files
	$(MAKE) -C docs -f Makefile.custom clean
	rm -rf tests/output test_results

.PHONY: check_windows_versions
check_windows_versions:  ## Check if our and upstream versions drifed apart
	tools/windows-versions.py check roles/install/vars/Windows.yml

.PHONY: update_windows_versions
update_windows_versions:  ## Update Windows versions in variable file
	tools/windows-versions.py update roles/install/vars/Windows.yml

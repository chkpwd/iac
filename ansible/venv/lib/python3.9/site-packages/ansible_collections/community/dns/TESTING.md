<!--
Copyright (c) Ansible Project
GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Running tests

## HostTech DNS modules

The CI (based on GitHub Actions) does not run integration tests for the HostTech modules, because they need access to HostTech API credentials. If you have some, copy [`tests/integration/integration_config.yml.hosttech-template`](https://github.com/ansible-collections/community.dns/blob/main/tests/integration/integration_config.yml.hosttech-template) to `integration_config.yml` in the same directory, and insert username, key, a test zone (`domain.ch`) and test record (`foo.domain.ch`). Then run `ansible-test integration --allow-unsupported hosttech`. Please note that the test record will be deleted, (re-)created, and finally deleted, so do not use any record you actually need!

To run the tests with Python 3.8:
```
ansible-test integration --docker default --python 3.8 --allow-unsupported hosttech
```
You can adjust the Python version, remove `--python 3.8` completely, use a different docker container, or remove `--docker default` completely.

## Hetzner DNS modules

The CI (based on GitHub Actions) does not run integration tests for the Hetzner modules, because they need access to Hetzner API credentials. If you have some, copy [`tests/integration/integration_config.yml.hetzner-template`](https://github.com/ansible-collections/community.dns/blob/main/tests/integration/integration_config.yml.hetzner-template) to `integration_config.yml` in the same directory, and insert API key and a test zone (`domain.de`). Then run `ansible-test integration --allow-unsupported hetzner`. Please note that the test zone will be modified, so do not use a zone you actually need!

To run the tests with Python 3.8:
```
ansible-test integration --docker default --python 3.8 --allow-unsupported hetzner
```
You can adjust the Python version, remove `--python 3.8` completely, use a different docker container, or remove `--docker default` completely.

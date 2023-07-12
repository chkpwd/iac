<!--
Copyright (c) Ansible Project
GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Community Hetzner Robot Collection
[![CI](https://github.com/ansible-collections/community.hrobot/workflows/CI/badge.svg?event=push)](https://github.com/ansible-collections/community.hrobot/actions) [![Codecov](https://img.shields.io/codecov/c/github/ansible-collections/community.hrobot)](https://codecov.io/gh/ansible-collections/community.hrobot)

This repository contains the `community.hrobot` Ansible Collection. The collection includes modules to work with [Hetzner's Robot](https://docs.hetzner.com/robot/).

You can find [documentation for the modules and plugins in this collection here](https://docs.ansible.com/ansible/devel/collections/community/hrobot/).

Please note that this collection does **not** support Windows targets.

## Tested with Ansible

Tested with the current Ansible 2.9, ansible-base 2.10, ansible-core 2.11, ansible-core 2.12, ansible-core 2.13, and ansible-core 2.14 releases and the current development version of ansible-core. Ansible versions before 2.9.10 are not supported.

## External requirements

A Hetzner Robot account.

## Collection Documentation

Browsing the [**latest** collection documentation](https://docs.ansible.com/ansible/latest/collections/community/hrobot) will show docs for the _latest version released in the Ansible package_, not the latest version of the collection released on Galaxy.

Browsing the [**devel** collection documentation](https://docs.ansible.com/ansible/devel/collections/community/hrobot) shows docs for the _latest version released on Galaxy_.

We also separately publish [**latest commit** collection documentation](https://ansible-collections.github.io/community.hrobot/branch/main/) which shows docs for the _latest commit in the `main` branch_.

If you use the Ansible package and do not update collections independently, use **latest**. If you install or update this collection directly from Galaxy, use **devel**. If you are looking to contribute, use **latest commit**.

## Included content

- `community.hrobot.failover_ip` module
- `community.hrobot.failover_ip_info` module
- `community.hrobot.firewall` module
- `community.hrobot.firewall_info` module
- `community.hrobot.hrobot` inventory plugin

You can find [documentation for the modules and plugins in this collection here](https://docs.ansible.com/ansible/devel/collections/community/hrobot/).

## Using this collection

Before using the General community collection, you need to install the collection with the `ansible-galaxy` CLI:

    ansible-galaxy collection install community.hrobot

You can also include it in a `requirements.yml` file and install it via `ansible-galaxy collection install -r requirements.yml` using the format:

```yaml
collections:
- name: community.hrobot
```

See [Ansible Using collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html) for more details.

## Contributing to this collection

If you want to develop new content for this collection or improve what is already here, the easiest way to work on the collection is to clone it into one of the configured [`COLLECTIONS_PATH`](https://docs.ansible.com/ansible/latest/reference_appendices/config.html#collections-paths), and work on it there.

You can find more information in the [developer guide for collections](https://docs.ansible.com/ansible/devel/dev_guide/developing_collections.html#contributing-to-collections), and in the [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html).

## Release notes

See the [changelog](https://github.com/ansible-collections/community.hrobot/tree/main/CHANGELOG.rst).

## More information

- [Ansible Collection overview](https://github.com/ansible-collections/overview)
- [Ansible User guide](https://docs.ansible.com/ansible/latest/user_guide/index.html)
- [Ansible Developer guide](https://docs.ansible.com/ansible/latest/dev_guide/index.html)
- [Ansible Collections Checklist](https://github.com/ansible-collections/overview/blob/master/collection_requirements.rst)
- [Ansible Community code of conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html)
- [The Bullhorn (the Ansible Contributor newsletter)](https://us19.campaign-archive.com/home/?u=56d874e027110e35dea0e03c1&id=d6635f5420)
- [Changes impacting Contributors](https://github.com/ansible-collections/overview/issues/45)

## Licensing

This collection is primarily licensed and distributed as a whole under the GNU General Public License v3.0 or later.

See [LICENSES/GPL-3.0-or-later.txt](https://github.com/ansible-collections/community.hrobot/blob/main/COPYING) for the full text.

Parts of the collection are licensed under the [BSD 2-Clause license](https://github.com/ansible-collections/community.hrobot/blob/main/LICENSES/BSD-2-Clause.txt).

All files have a machine readable `SDPX-License-Identifier:` comment denoting its respective license(s) or an equivalent entry in an accompanying `.license` file. Only changelog fragments (which will not be part of a release) are covered by a blanket statement in `.reuse/dep5`. This conforms to the [REUSE specification](https://reuse.software/spec/).

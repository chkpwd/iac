![Collection integration](https://github.com/ngine-io/ansible-collection-exoscale/workflows/Collection%20integration/badge.svg)
 [![Codecov](https://img.shields.io/codecov/c/github/ngine-io/ansible-collection-exoscale)](https://codecov.io/gh/ngine-io/ansible-collection-exoscale)
[![License](https://img.shields.io/badge/license-GPL%20v3.0-brightgreen.svg)](LICENSE)

# Ansible Collection for exoscale Cloud

This collection provides a series of Ansible modules and plugins for interacting with the [exoscale](https://www.exoscale.com) Cloud.

## Requirements

- ansible version >= 2.9

## Installation

To install the collection hosted in Galaxy:

```bash
ansible-galaxy collection install ngine_io.exoscale
```

To upgrade to the latest version of the collection:

```bash
ansible-galaxy collection install ngine_io.exoscale --force
```

## Usage

### Playbooks

To use a module from exoscale collection, please reference the full namespace, collection name, and modules name that you want to use:

```yaml
---
- name: Using exoscale collection
  hosts: localhost
  tasks:
    - ngine_io.exoscale.<module>:
      ...
```

Or you can add full namepsace and collecton name in the `collections` element:

```yaml
---
- name: Using exoscale collection
  hosts: localhost
  collections:
    - ngine_io.exoscale
  tasks:
    - <module>:
      ...
```

### Roles

For existing Ansible roles, please also reference the full namespace, collection name, and modules name which used in tasks instead of just modules name.

## Contributing

There are many ways in which you can participate in the project, for example:

- Submit bugs and feature requests, and help us verify as they are checked in
- Review source code changes
- Review the documentation and make pull requests for anything from typos to new content
- If you are interested in fixing issues and contributing directly to the code base, please see the [CONTRIBUTING](CONTRIBUTING.md) document.

## License

GNU General Public License v3.0

See [COPYING](COPYING) to see the full text.

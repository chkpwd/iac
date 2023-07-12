![CI](https://github.com/ServiceNowITOM/servicenow-ansible/workflows/CI/badge.svg)

# Ansible Collection for ServiceNow
This collection provides a series of Ansible modules, roles, and plugins for interacting with [ServiceNow](https://servicenow.com)

## Requirements
 - ansible version >= 2.9
 - pysnow
 - requests
 - netaddr

## Installation

To install ServiceNow collection hosted in Galaxy:

```bash
ansible-galaxy collection install servicenow.servicenow
```

To upgrade to the latest version of ServiceNow collection:

```bash
ansible-galaxy collection install servicenow.servicenow --force
```
## Usage

### Playbooks

To use a module from the ServiceNow collection, please reference the fill namespace, collection name, and module name that you want to use:

```yaml
---
- name: Using ServiceNow Collection
  hosts: localhost
  gather_facts: no
  
  tasks:
  - name: Create an incident
    servicenow.servicenow.snow_record:
      username: ansible_test
      password: my_password
      instance: dev99999
      state: present
      data:
        short_description: "This is a test incident opened by Ansible"
        severity: 3
        priority: 2
```

Or you can add full namespace and collection name in the `collections` section:

```yaml
---
- name: Using ServiceNow Collection
  hosts: localhost
  gather_facts: no
  collections:
    - servicenow.servicenow
  
  tasks:
  - name: Create an incident
    snow_record:
      username: ansible_test
      password: my_password
      instance: dev99999
      state: present
      data:
        short_description: "This is a test incident opened by Ansible"
        severity: 3
        priority: 2
```

### Roles

For existing Ansible roles, please also reference the full namespace, collection name, and modules name which used in tasks instead of just modules name.

## Resource Included

### Modules
- [snow_record](docs/snow_record.md) - Creates, deletes and updates a single record in ServiceNow.
- [snow_record_find](docs/snow_record_find.md) - Gets multiple records from a specified table from ServiceNow based on a query dictionary.

### Plugins
-  [now](docs/inventory.md) - ServiceNow Inventory Plugin

## Contributing

There are many ways in which you can participate in the project, for example:

- Submit bugs and feature requests, and help us verify as they are checked in
- Review source code changes
- Review the documentation and make pull requests for anything from typos to new content

Special thanks to Tim Rightnour (@garbled1) for the original version of ServiceNow modules in Ansible Core.

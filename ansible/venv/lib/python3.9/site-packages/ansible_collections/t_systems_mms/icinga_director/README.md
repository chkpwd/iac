# Icinga Director Collection for Ansible

[![ci-ansible-test](https://github.com/T-Systems-MMS/ansible-collection-icinga-director/workflows/ansible-test/badge.svg)](https://github.com/T-Systems-MMS/ansible-collection-icinga-director/actions?query=workflow%3Aansible-test)
[![codecov](https://codecov.io/gh/T-Systems-MMS/ansible-collection-icinga-director/branch/master/graph/badge.svg)](https://codecov.io/gh/T-Systems-MMS/ansible-collection-icinga-director)

This Ansible collection contains:

1. Ansible [modules](plugins/modules/) to change objects in Icinga 2 using the director API. 
Additionally all supported modules have an appropriate `*_info`-module to gather facts about the existing objects in the director.

    * `icinga_command_template`
    * `icinga_command`
    * `icinga_endpoint`
    * `icinga_host_template`
    * `icinga_host`
    * `icinga_hostgroup`
    * `icinga_notification`
    * `icinga_notification_template`
    * `icinga_service`
    * `icinga_service_apply`
    * `icinga_service_template`
    * `icinga_servicegroup`
    * `icinga_serviceset`
    * `icinga_timeperiod`
    * `icinga_timeperiod_template`
    * `icinga_user_group`
    * `icinga_user_template`
    * `icinga_user`
    * `icinga_zone`

2. A module to deploy changes in the director and a corresponding info-module.

3. A [role](roles/ansible_icinga/) to change objects in Icinga 2 using the the provided modules.

4. An [inventory plugin](plugins/inventory) to use hosts and groups defined in Icinga as a dynamic inventory.

Required Ansible version: 2.9.10

## Installation

If you use Ansible >=3.0.0, this collection is included in Ansible.

If you use an older version, you can install it with Ansible Galaxy:

```
ansible-galaxy collection install t_systems_mms.icinga_director
```

Alternatively put the collection into a `requirements.yml`-file:

```
---
collections:
- t_systems_mms.icinga_director
```

## Documentation

Our modules include documentation.

You can find the complete documentation for the modules in the [docs-folder](docs) or in the [Ansible documentation](<https://docs.ansible.com/ansible/latest/collections/t_systems_mms/icinga_director/index.html#plugins-in-t-systems-mms-icinga-director>).

To display it on the command-line you can use the `ansible-doc` command.

For example, to see the documentation for the module `icinga_host` run the following command on the cli:

```
ansible-doc t_systems_mms.icinga_director.icinga_host
```

To see the documentation for the inventory plugin, run:

```
ansible-doc -t inventory t_systems_mms.icinga_director.icinga_director_inventory
```

## Examples using the modules

See the `examples` directory for a complete list of examples.

```
- hosts: localhost
  collections:
    - t_systems_mms.icinga_director
  tasks:
    - name: create a host in icinga
      t_systems_mms.icinga_director.icinga_host:
        state: present
        url: "https://example.com"
        url_username: "{{ icinga_user }}"
        url_password: "{{ icinga_pass }}"
        object_name: "{{ ansible_hostname }}"
        address: "{{ ansible_default_ipv4.address }}"
        display_name: "{{ ansible_hostname }}"
        groups:
          - "foo"
        imports:
          - "StandardServer"
        vars:
          dnscheck: "no"
```

```
- name: Query a service apply rule in icinga
  t_systems_mms.icinga_director.icinga_service_apply_info:
    url: "{{ icinga_url }}"
    url_username: "{{ icinga_user }}"
    url_password: "{{ icinga_pass }}"
    query: "SERVICE_dummy"
  register: result
```

## Examples using the role

Please see the [README](roles/ansible_icinga/README.md) of the role.

## Examples using the inventory plugin

Create a file that ends with `icinga_director_inventory.yaml`, for example `inventory.icinga_director_inventory.yaml`.

The content should look like this:

```
plugin: t_systems_mms.icinga_director.icinga_director_inventory
url: "https://example.com"
url_username: foo
url_password: bar
force_basic_auth: False
```

Then you can use the dynamic inventory like this:

```
ansible-playbook -i inventory.icinga_director_inventory.yaml path/to/your/playbook.yml
```

## Example using module defaults groups

With ansible-core >= 2.12 it is possible to specify defaults parameters for all modules in this collection using [Module defaults groups](https://docs.ansible.com/ansible/latest/user_guide/playbooks_module_defaults.html#module-defaults-groups). Use it like this:

```
- hosts: localhost

  module_defaults:
    group/t_systems_mms.icinga_director.icinga:
      url: "https://example.com"
      url_username: foo
      url_password: bar

  tasks:
    - name: Create host
      t_systems_mms.icinga_director.icinga_host:
        object_name: myhost
        address: 172.0.0.1

    - name: Create command
      t_systems_mms.icinga_director.icinga_command:
        object_name: my-command
        command: my-command.sh
```

## Contributing

See [Contributing](CONTRIBUTING.md).

## Troubleshooting

If one of the following errors is thrown, your Icinga Director is probably sitting behind a basic authentication prompt. Use `force_basic_auth: true` in your tasks to fix the problem.
If you are using this collections' ansible role, you have to use `icinga_force_basic_auth: true` to fix this problem.

```
fatal: [localhost]: FAILED! => {"changed": false, "msg": "bad return code while creating: -1. Error message: Request failed: <urlopen error Tunnel connection failed: 302 Found>"}
```

```
failed: [localhost] => {"ansible_loop_var": "item", "changed": false, "item": "localhost", "msg": "AbstractDigestAuthHandler does not support the following scheme: 'Negotiate'", "status": -1, "url": "https://icinga-director.example.com/director/host?name=foohost"}
```


## Extras

* Use our code snippets template supported in Visual Studio Code

Please see the [README](vsc-snippets/README.md) for more information.

## License

GPLv3

## Author Information

* Sebastian Gumprich
* Lars Krahl
* Michaela Mattes
* Martin Schurz

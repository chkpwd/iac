# CISCO ASA Ansible Collection

[![CI](https://zuul-ci.org/gated.svg)](https://dashboard.zuul.ansible.com/t/ansible/project/github.com/ansible-collections/cisco.asa) <!--[![Codecov](https://img.shields.io/codecov/c/github/ansible-collections/cisco)](https://codecov.io/gh/ansible-collections/cisco.asa)-->

The Ansible Cisco ASA collection includes a variety of Ansible content to help automate the management of Cisco ASA firewall appliances.

<!--start requires_ansible-->
## Ansible version compatibility

This collection has been tested against following Ansible versions: **>=2.9.10**.

For collections that support Ansible 2.9, please ensure you update your `network_os` to use the
fully qualified collection name (for example, `cisco.ios.ios`).
Plugins and modules within a collection may be tested with only specific Ansible versions.
A collection may contain metadata that identifies these versions.
PEP440 is the schema used to describe the versions of Ansible.
<!--end requires_ansible-->

## Tested with Ansible

This collection has been tested against Cisco ASA 9.10(1)11 and Cisco ASA image configured over Zuul with version 9.12.3.

<!-- List the versions of Ansible the collection has been tested with. Must match what is in galaxy.yml. -->

## External requirements

<!-- List any external resources the collection depends on, for example minimum versions of an OS, libraries, or utilities. Do not list other Ansible collections here. -->

### Supported connections

The Cisco ASA collection supports `network_cli` connections.

## Included content

<!--start collection content-->
### Cliconf plugins
Name | Description
--- | ---
[cisco.asa.asa](https://github.com/ansible-collections/cisco.asa/blob/main/docs/cisco.asa.asa_cliconf.rst)|Use asa cliconf to run command on Cisco ASA platform

### Modules
Name | Description
--- | ---
[cisco.asa.asa_acls](https://github.com/ansible-collections/cisco.asa/blob/main/docs/cisco.asa.asa_acls_module.rst)|Access-Lists resource module
[cisco.asa.asa_command](https://github.com/ansible-collections/cisco.asa/blob/main/docs/cisco.asa.asa_command_module.rst)|Run arbitrary commands on Cisco ASA devices
[cisco.asa.asa_config](https://github.com/ansible-collections/cisco.asa/blob/main/docs/cisco.asa.asa_config_module.rst)|Manage configuration sections on Cisco ASA devices
[cisco.asa.asa_facts](https://github.com/ansible-collections/cisco.asa/blob/main/docs/cisco.asa.asa_facts_module.rst)|Collect facts from remote devices running Cisco ASA
[cisco.asa.asa_ogs](https://github.com/ansible-collections/cisco.asa/blob/main/docs/cisco.asa.asa_ogs_module.rst)|Object Group resource module

<!--end collection content-->

## Installing this collection

You can install the Cisco ASA collection with the Ansible Galaxy CLI:

    ansible-galaxy collection install cisco.asa

You can also include it in a `requirements.yml` file and install it with `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
---
collections:
  - name: cisco.asa
```

## Using this collection

This collection includes [security resource modules](https://docs.ansible.com/ansible/latest/network/user_guide/network_resource_modules.html). Similar to Network resource modules introduced in Ansible `2.9`

### Using Cisco ASA Ansible Collection

An example for using this collection to manage a ACL resource
[Cisco ASA](https://www.cisco.com/c/en/us/td/docs/security/asa/asa90/configuration/guide/asa_90_cli_config/acl_extended.html)
is as follows:

`inventory.ini` (Note the password should be managed by a [Vault](https://docs.ansible.com/ansible/latest/user_guide/vault.html) for a production environment.

```
[asa01]
host_asa.example.com

[asa01:vars]
ansible_user=admin
ansible_ssh_pass=password
ansible_become=true
ansible_become_method=ansible.netcommon.enable
ansible_become_pass=become_password
ansible_connection=ansible.netcommon.network_cli
ansible_network_os=cisco.asa.asa
ansible_python_interpreter=python
```

#### Using the modules with Fully Qualified Collection Name (FQCN)

You can either call modules by their Fully Qualified Collection Namespace (FQCN), like `cisco.asa.asa_acls`, or you can call modules by their short name if you list the `cisco.asa` collection in the playbook's `collections`, as follows:

```yaml
---
- hosts: asa01
  gather_facts: false
  connection: network_cli

  collections:
    - cisco.asa

  tasks:
    - name: Merge the provided configuration with the existing running configuration
      register: result
      cisco.asa.asa_acls: &id001
        config:
          - acls:
              - name: test_global_access
                acl_type: extended
                aces:
                  - grant: deny
                    line: 1
                    protocol: tcp
                    protocol_options:
                      tcp: true
                    source:
                      address: 192.0.2.0
                      netmask: 255.255.255.0
                    destination:
                      address: 192.0.3.0
                      netmask: 255.255.255.0
                      port_protocol:
                        eq: www
                    log: default
              - name: test_R1_traffic
                acl_type: extended
                aces:
                  - grant: deny
                    line: 1
                    protocol_options:
                      tcp: true
                    source:
                      address: 2001:db8:0:3::/64
                      port_protocol:
                        eq: www
                    destination:
                      address: 2001:fc8:0:4::/64
                      port_protocol:
                        eq: telnet
                    inactive: true
        state: merged
```

The following example task replaces configuration changes in the existing configuration on a Cisco ASA firewall device, using the FQCN:

```yaml
---
- name: Replace device configurations of listed ACLs with provided configurations
  register: result
  cisco.asa.asa_acls: &id001
    config:
      - acls:
          - name: test_global_access
            acl_type: extended
            aces:
              - grant: deny
                line: 1
                protocol_options:
                tcp: true
                source:
                  address: 192.0.4.0
                  netmask: 255.255.255.0
                  port_protocol:
                    eq: telnet
                destination:
                  address: 192.0.5.0
                  netmask: 255.255.255.0
                  port_protocol:
                    eq: www
    state: replaced
```

## Contributing to this collection

We welcome community contributions to this collection. If you find problems, please open an issue or create a PR against the [Cisco ASA collection repository](https://github.com/ansible-collections/cisco.asa). See [Contributing to Ansible-maintained collections](https://docs.ansible.com/ansible/devel/community/contributing_maintained_collections.html#contributing-maintained-collections) for complete details.

You can also join us on:

- IRC - the `#ansible-security` [libera.chat](https://libera.chat/) channel

See the [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html) for details on contributing to Ansible.

### Code of Conduct

This collection follows the Ansible project's
[Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html).
Please read and familiarize yourself with this document.

## Release notes

<!--Add a link to a changelog.md file or an external docsite to cover this information. -->

Release notes are available [here](https://github.com/ansible-collections/cisco.asa/blob/main/CHANGELOG.rst).

## Roadmap

<!-- Optional. Include the roadmap for this collection, and the proposed release/versioning strategy so users can anticipate the upgrade/update cycle. -->

## More information

- [Ansible Collection overview](https://github.com/ansible-collections/overview)
- [Ansible User guide](https://docs.ansible.com/ansible/latest/user_guide/index.html)
- [Ansible Developer guide](https://docs.ansible.com/ansible/latest/dev_guide/index.html)
- [Ansible Community code of conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html)

## Licensing

GNU General Public License v3.0 or later.

See [LICENSE](https://www.gnu.org/licenses/gpl-3.0.txt) to see the full text.

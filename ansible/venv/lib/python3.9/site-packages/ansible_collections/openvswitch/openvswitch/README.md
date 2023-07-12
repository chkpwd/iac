

# Open vSwitch Collection
[![CI](https://zuul-ci.org/gated.svg)](https://dashboard.zuul.ansible.com/t/ansible/project/github.com/ansible-collections/openvswitch.openvswitch) <!--[![Codecov](https://img.shields.io/codecov/c/github/ansible-collections/vyos)](https://codecov.io/gh/ansible-collections/openvswitch.openvswitch)-->

The Open vSwitch collection includes a variety of Ansible content to help automate the management of Open vSwitch.

<!--start requires_ansible-->
## Ansible version compatibility

This collection has been tested against following Ansible versions: **>=2.9.10**.

For collections that support Ansible 2.9, please ensure you update your `network_os` to use the
fully qualified collection name (for example, `cisco.ios.ios`).
Plugins and modules within a collection may be tested with only specific Ansible versions.
A collection may contain metadata that identifies these versions.
PEP440 is the schema used to describe the versions of Ansible.
<!--end requires_ansible-->

### Supported connections
The Open vSwitch collection supports local connections only.

## Included content

Click the ``Content`` button to see the list of content included in this collection.

<!--start collection content-->
### Modules
Name | Description
--- | ---
[openvswitch.openvswitch.openvswitch_bond](https://github.com/ansible-collections/openvswitch.openvswitch/blob/main/docs/openvswitch.openvswitch.openvswitch_bond_module.rst)|Manage Open vSwitch bonds
[openvswitch.openvswitch.openvswitch_bridge](https://github.com/ansible-collections/openvswitch.openvswitch/blob/main/docs/openvswitch.openvswitch.openvswitch_bridge_module.rst)|Manage Open vSwitch bridges
[openvswitch.openvswitch.openvswitch_db](https://github.com/ansible-collections/openvswitch.openvswitch/blob/main/docs/openvswitch.openvswitch.openvswitch_db_module.rst)|Configure open vswitch database.
[openvswitch.openvswitch.openvswitch_port](https://github.com/ansible-collections/openvswitch.openvswitch/blob/main/docs/openvswitch.openvswitch.openvswitch_port_module.rst)|Manage Open vSwitch ports

<!--end collection content-->

## Installing this collection

You can install the Open vSwitch collection with the Ansible Galaxy CLI:

    ansible-galaxy collection install openvswitch.openvswitch

You can also include it in a `requirements.yml` file and install it with `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
---
collections:
  - name: openvswitch.openvswitch
```
## Using this collection

You can call modules by their Fully Qualified Collection Namespace (FQCN), such as `openvswitch.openvswitch.openvswitch_port`.
The following example task replaces configuration changes in the existing configuration on a Open vSwitch network device, using the FQCN:

```yaml
---
  - name: Creates port eth2 on bridge br-ex
    openvswitch.openvswitch.openvswitch_port:
      bridge: br-ex
      port: eth2
    state: present
```

**NOTE**: For Ansible 2.9, you may not see deprecation warnings when you run your playbooks with this collection. Use this documentation to track when a module is deprecated.


### See Also:

* [Ansible Using collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html) for more details.

## Contributing to this collection

We welcome community contributions to this collection. If you find problems, please open an issue or create a PR against the [Open vSwitch collection repository](https://github.com/ansible-collections/openvswitch.openvswitch). See [Contributing to Ansible-maintained collections](https://docs.ansible.com/ansible/devel/community/contributing_maintained_collections.html#contributing-maintained-collections) for complete details.

You can also join us on:

- IRC - the ``#ansible-network`` [irc.libera.chat](https://libera.chat/) channel
- Slack - https://ansiblenetwork.slack.com

See the [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html) for details on contributing to Ansible.

### Code of Conduct
This collection follows the Ansible project's
[Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html).
Please read and familiarize yourself with this document.


## Changelogs

Release notes are available [here](https://github.com/ansible-collections/openvswitch.openvswitch/blob/main/changelogs/CHANGELOG.rst).

## Roadmap

<!-- Optional. Include the roadmap for this collection, and the proposed release/versioning strategy so users can anticipate the upgrade/update cycle. -->

## More information

- [Ansible network resources](https://docs.ansible.com/ansible/latest/network/getting_started/network_resources.html)
- [Ansible Collection overview](https://github.com/ansible-collections/overview)
- [Ansible User guide](https://docs.ansible.com/ansible/latest/user_guide/index.html)
- [Ansible Developer guide](https://docs.ansible.com/ansible/latest/dev_guide/index.html)
- [Ansible Community code of conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html)

## Licensing

GNU General Public License v3.0 or later.

See [LICENSE](https://www.gnu.org/licenses/gpl-3.0.txt) to see the full text.

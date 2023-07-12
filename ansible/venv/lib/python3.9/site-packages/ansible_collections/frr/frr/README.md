

# Free Range Routing (FRR) Collection
[![CI](https://zuul-ci.org/gated.svg)](https://dashboard.zuul.ansible.com/t/ansible/project/github.com/ansible-collections/frr.frr)
[![Codecov](https://codecov.io/gh/ansible-collections/frr.frr/branch/main/graph/badge.svg)](https://codecov.io/gh/ansible-collections/frr.frr)


The Ansible FRR collection includes a variety of Ansible content to help automate the management of FRR network appliances.

This collection has been tested against FRR 6.0.

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
The FRR collection supports ``network_cli`` connections.

## Included content
<!--start collection content-->
### Cliconf plugins
Name | Description
--- | ---
[frr.frr.frr](https://github.com/ansible-collections/frr.frr/blob/main/docs/frr.frr.frr_cliconf.rst)|Use frr cliconf to run command on Free Range Routing platform

### Modules
Name | Description
--- | ---
[frr.frr.frr_bgp](https://github.com/ansible-collections/frr.frr/blob/main/docs/frr.frr.frr_bgp_module.rst)|Configure global BGP settings on Free Range Routing(FRR).
[frr.frr.frr_facts](https://github.com/ansible-collections/frr.frr/blob/main/docs/frr.frr.frr_facts_module.rst)|Collect facts from remote devices running Free Range Routing (FRR).

<!--end collection content-->

Click the ``Content`` button to see the list of content included in this collection.

## Installing this collection

You can install the FRR collection with the Ansible Galaxy CLI:

    ansible-galaxy collection install frr.frr

You can also include it in a `requirements.yml` file and install it with `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
---
collections:
  - name: frr.frr
```
## Using this collection

You can call modules by their Fully Qualified Collection Namespace (FQCN), such as `frr.frr.frr_bgp`.
The following example task replaces configuration changes in the existing configuration on a FRR network device, using the FQCN:

```yaml
---
  - name: configure global bgp as 64496
    frr.frr.frr_bgp:
      config:
        bgp_as: 64496
        router_id: 192.0.2.1
        log_neighbor_changes: True
        neighbors:
          - neighbor: 192.51.100.1
            remote_as: 64497
            timers:
              keepalive: 120
              holdtime: 360
          - neighbor: 198.51.100.2
            remote_as: 64498
        networks:
          - prefix: 192.0.2.0
            masklen: 24
            route_map: RMAP_1
          - prefix: 198.51.100.0
            masklen: 24
        address_family:
          - afi: ipv4
            safi: unicast
            redistribute:
              - protocol: ospf
                id: 223
                metric: 10
      operation: merge
```

**NOTE**: For Ansible 2.9, you may not see deprecation warnings when you run your playbooks with this collection. Use this documentation to track when a module is deprecated.


### See Also:

* [FRR Platform Options](https://docs.ansible.com/ansible/latest/network/user_guide/platform_frr.html)
* [Ansible Using collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html) for more details.

## Contributing to this collection

We welcome community contributions to this collection. If you find problems, please open an issue or create a PR against the [FRR collection repository](https://github.com/ansible-collections/frr.frr). See [Contributing to Ansible-maintained collections](https://docs.ansible.com/ansible/devel/community/contributing_maintained_collections.html#contributing-maintained-collections) for complete details.

You can also join us on:

- IRC - the ``#ansible-network`` [irc.libera.chat](https://libera.chat/) channel
- Slack - https://ansiblenetwork.slack.com

See the [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html) for details on contributing to Ansible.

### Code of Conduct
This collection follows the Ansible project's
[Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html).
Please read and familiarize yourself with this document.


## Changelogs

Release notes are available [here](https://github.com/ansible-collections/frr.frr/blob/main/changelogs/CHANGELOG.rst).

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

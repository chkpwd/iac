# community.fortios Collection
<!-- Add CI and code coverage badges here. Samples included below. -->
[![CI](https://github.com/ansible-collections/community.fortios/workflows/CI/badge.svg?event=push)](https://github.com/ansible-collections/community.fortios/actions) [![Codecov](https://img.shields.io/codecov/c/github/ansible-collections/community.fortios)](https://codecov.io/gh/ansible-collections/community.fortios)

<!-- Describe the collection and why a user would want to use it. What does the collection do? -->

This repo hosts the `community.fortios` Ansible Collection.

The collection includes a variety of Ansible content to automate the management of FortiOS devices.

## Tested with Ansible

<!-- List the versions of Ansible the collection has been tested with. Must match what is in galaxy.yml. -->

- `2.9`
- `2.10`
- `devel`

## External requirements

<!-- List any external resources the collection depends on, for example minimum versions of an OS, libraries, or utilities. Do not list other Ansible collections here. -->

- None

<!-- ### Supported connections -->

<!-- Optional. If your collection supports only specific connection types (such as HTTPAPI, netconf, or others), list them here. -->

##  Included Content

- **Modules**:
  - `faz_device`
  - `fmgr_device`
  - `fmgr_device_config`
  - `fmgr_device_group`
  - `fmgr_device_provision_template`
  - `fmgr_fwobj_address`
  - `fmgr_fwobj_ippool`
  - `fmgr_fwobj_ippool6`
  - `fmgr_fwobj_service`
  - `fmgr_fwobj_vip`
  - `fmgr_fwpol_ipv4`
  - `fmgr_fwpol_package`
  - `fmgr_ha`
  - `fmgr_provisioning`
  - `fmgr_query`
  - `fmgr_script`
  - `fmgr_secprof_appctrl`
  - `fmgr_secprof_av`
  - `fmgr_secprof_dns`
  - `fmgr_secprof_ips`
  - `fmgr_secprof_profile_group`
  - `fmgr_secprof_proxy`
  - `fmgr_secprof_spam`
  - `fmgr_secprof_ssl_ssh`
  - `fmgr_secprof_voip`
  - `fmgr_secprof_waf`
  - `fmgr_secprof_wanopt`
  - `fmgr_secprof_web`

## Using this collection

<!--Include some quick examples that cover the most common use cases for your collection content. -->

See [Ansible Using collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html) for more details.

## Contributing to this collection

<!--Describe how the community can contribute to your collection. At a minimum, include how and where users can create issues to report problems or request features for this collection.  List contribution requirements, including preferred workflows and necessary testing, so you can benefit from community PRs. If you are following general Ansible contributor guidelines, you can link to - [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html). -->

[Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html)

## Release notes

See the [changelog](https://github.com/ansible-collections/community.fortios/tree/main/CHANGELOG.rst).

<!-- ## Roadmap -->

<!-- Optional. Include the roadmap for this collection, and the proposed release/versioning strategy so users can anticipate the upgrade/update cycle. -->

## More information

<!-- List out where the user can find additional information, such as working group meeting times, slack/IRC channels, or documentation for the product this collection automates. At a minimum, link to: -->

- [Ansible Collection overview](https://github.com/ansible-collections/overview)
- [Ansible User guide](https://docs.ansible.com/ansible/latest/user_guide/index.html)
- [Ansible Developer guide](https://docs.ansible.com/ansible/latest/dev_guide/index.html)
- [Ansible Collections Checklist](https://github.com/ansible-collections/overview/blob/master/collection_requirements.rst)
- [Ansible Community code of conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html)
- [The Bullhorn (the Ansible Contributor newsletter)](https://us19.campaign-archive.com/home/?u=56d874e027110e35dea0e03c1&id=d6635f5420)
- [Changes impacting Contributors](https://github.com/ansible-collections/overview/issues/45)

## Licensing

<!-- Include the appropriate license information here and a pointer to the full licensing details. If the collection contains modules migrated from the ansible/ansible repo, you must use the same license that existed in the ansible/ansible repo. See the GNU license example below. -->

GNU General Public License v3.0 or later.

See [LICENSE](https://www.gnu.org/licenses/gpl-3.0.txt) to see the full text.

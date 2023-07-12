# Community SAP Collection

This repository contains the community.sap Ansible Collection. The collection includes modules and plugins supported by the Ansible SAP community to help SAP landscape management.

# SAP Collection for Ansible
<!-- Add CI and code coverage badges here. Samples included below. -->
[![CI](https://github.com/ansible-collections/community.sap/workflows/CI/badge.svg?event=push)](https://github.com/ansible-collections/community.sap/actions) [![Codecov](https://img.shields.io/codecov/c/github/ansible-collections/community.sap)](https://codecov.io/gh/ansible-collections/community.sap)

<!-- Describe the collection and why a user would want to use it. What does the collection do? -->

## Code of Conduct

We follow the [Ansible Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html) in all our interactions within this project.

If you encounter abusive behavior, please refer to the [policy violations](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html#policy-violations) section of the Code for information on how to raise a complaint.

## Communication

<!--List available communication channels. In addition to channels specific to your collection, we also recommend to use the following ones.-->

We announce releases and important changes through Ansible's [The Bullhorn newsletter](https://github.com/ansible/community/wiki/News#the-bullhorn). Be sure you are [subscribed](https://eepurl.com/gZmiEP).

Join us in the `#ansible` (general use questions and support), `#ansible-community` (community and collection development questions), and other [Matrix/LiberaChat IRC channels](https://docs.ansible.com/ansible/devel/community/communication.html#real-time-chat).

We take part in the global quarterly [Ansible Contributor Summit](https://github.com/ansible/community/wiki/Contributor-Summit) virtually or in-person. Track [The Bullhorn newsletter](https://eepurl.com/gZmiEP) and join us.

For more information about communication, refer to the [Ansible Communication guide](https://docs.ansible.com/ansible/devel/community/communication.html).

## Contributing to this collection

<!--Describe how the community can contribute to your collection. At a minimum, fill up and include the CONTRIBUTING.md file containing how and where users can create issues to report problems or request features for this collection. List contribution requirements, including preferred workflows and necessary testing, so you can benefit from community PRs. If you are following general Ansible contributor guidelines, you can link to - [Ansible Community Guide](https://docs.ansible.com/ansible/devel/community/index.html). List the current maintainers (contributors with write or higher access to the repository). The following can be included:-->

The content of this collection is made by people like you, a community of individuals collaborating on making the world better through developing automation software.

We are actively accepting new contributors.

Any kind of contribution is very welcome.

You don't know how to start? Refer to our [contribution guide](CONTRIBUTING.md)!

We use the following guidelines:

* [CONTRIBUTING.md](CONTRIBUTING.md)
* [REVIEW_CHECKLIST.md](REVIEW_CHECKLIST.md)
* [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html)
* [Ansible Development Guide](https://docs.ansible.com/ansible/devel/dev_guide/index.html)
* [Ansible Collection Development Guide](https://docs.ansible.com/ansible/devel/dev_guide/developing_collections.html#contributing-to-collections)

## Collection maintenance

The current maintainers are listed in the [MAINTAINERS](MAINTAINERS) file. If you have questions or need help, feel free to mention them in the proposals.

To learn how to maintain / become a maintainer of this collection, refer to the [Maintainer guidelines](MAINTAINING.md).

## Governance

<!--Describe how the collection is governed. Here can be the following text:-->

The process of decision making in this collection is based on discussing and finding consensus among participants.

Every voice is important. If you have something on your mind, create an issue or dedicated discussion and let's discuss it!

## Tested with Ansible and the following Python versions

Tested Ansible versions:
- 2.9
- 2.10
- 2.11
- 2.12
- devel

Tested Python versions:
- 2.6
- 2.7
- 3.5
- 3.6
- 3.7
- 3.8
- 3.9

Due to SAP licensing and hardware requirements, integration tests are momentarily not feasible.
The modules are tested manually against SAP systems until we found a solution or have some
modules where we are able to execute integration test we decided to disable these tests.

## External requirements

For some modules the below requirements are needed on the host that executes a module.

- pyrfc >= 2.4.0
- SAPCAR
- SAPCONTROL

### Supported connections
<!-- Optional. If your collection supports only specific connection types (such as HTTPAPI, netconf, or others), list them here. -->

## Included content

- **Modules**:
  - [hana_query](https://docs.ansible.com/ansible/latest/collections/community/sap/hana_query.html)
  - [sap_task_list_execute](https://docs.ansible.com/ansible/latest/collections/community/sap/sap_task_list_execute.html)
  - [sapcar_extract](https://docs.ansible.com/ansible/latest/collections/community/sap/sapcar_extract.html)
  - [sap_company](https://docs.ansible.com/ansible/latest/collections/community/sap/sap_company.html)
  - [sap_snote](https://docs.ansible.com/ansible/latest/collections/community/sap/sap_snote.html)
  - [sap_user](https://docs.ansible.com/ansible/latest/collections/community/sap/sap_user.html)
  - [sap_system_facts](https://docs.ansible.com/ansible/latest/collections/community/sap/sap_system_facts.html)

## Using this collection

<!--Include some quick examples that cover the most common use cases for your collection content. It can include the following examples of installation and upgrade (change NAMESPACE.COLLECTION_NAME correspondingly):-->

### Installing the Collection from Ansible Galaxy

Before using this collection, you need to install it with the Ansible Galaxy command-line tool:
```bash
ansible-galaxy collection install community.sap
```

You can also include it in a `requirements.yml` file and install it with `ansible-galaxy collection install -r requirements.yml`, using the format:
```yaml
---
collections:
  - name: community.sap
```

Note that if you install the collection from Ansible Galaxy, it will not be upgraded automatically when you upgrade the `ansible` package. To upgrade the collection to the latest available version, run the following command:
```bash
ansible-galaxy collection install community.sap --upgrade
```

You can also install a specific version of the collection, for example, if you need to downgrade when something is broken in the latest version (please report an issue in this repository). Use the following syntax to install version `0.1.0`:

```bash
ansible-galaxy collection install community.sap:==0.1.0
```

See [Ansible Using collections](https://docs.ansible.com/ansible/devel/user_guide/collections_using.html) for more details.

## Release notes

See the [changelog](https://github.com/ansible-collections/community.sap/tree/main/CHANGELOG.rst).

## Releasing, Versioning and Deprecation
This collection follows Semantic Versioning. More details on versioning can be found in the Ansible docs.

We plan to regularly release new minor or bugfix versions once new features or bugfixes have been implemented.

Releasing the current major version happens from the main branch. We will create a stable-1 branch for 1.x.y versions once we start working on a 2.0.0 release, to allow backporting bugfixes and features from the 2.0.0 branch (main) to stable-1.

For reference have a look at the issue [Releasing, Versioning and Deprecation](https://github.com/ansible-collections/community.sap/issues/4).



## Roadmap

Please have a look at the project board.

## More information

<!-- List out where the user can find additional information, such as working group meeting times, slack/IRC channels, or documentation for the product this collection automates. At a minimum, link to: -->

- [Ansible Collection overview](https://github.com/ansible-collections/overview)
- [Ansible User guide](https://docs.ansible.com/ansible/devel/user_guide/index.html)
- [Ansible Developer guide](https://docs.ansible.com/ansible/devel/dev_guide/index.html)
- [Ansible Collections Checklist](https://github.com/ansible-collections/overview/blob/master/collection_requirements.rst)
- [Ansible Community Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html)
- [The Bullhorn (the Ansible Contributor newsletter)](https://us19.campaign-archive.com/home/?u=56d874e027110e35dea0e03c1&id=d6635f5420)
- [News for Maintainers](https://github.com/ansible-collections/news-for-maintainers)

## Licensing

<!-- Include the appropriate license information here and a pointer to the full licensing details. If the collection contains modules migrated from the ansible/ansible repo, you must use the same license that existed in the ansible/ansible repo. See the GNU license example below. -->

GNU General Public License v3.0 or later.

See [LICENSE](https://www.gnu.org/licenses/gpl-3.0.txt) to see the full text.

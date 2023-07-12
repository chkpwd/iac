# Ansible Modules for Dell Technologies PowerFlex

The Ansible Modules for Dell Technologies (Dell) PowerFlex allow Data Center and IT administrators to use RedHat Ansible to automate and orchestrate the provisioning and management of Dell PowerFlex storage systems.

The capabilities of the Ansible modules are managing SDCs, volumes, snapshots, storage pools, replication consistency groups, replication pairs, SDSs, devices, protection domains, MDM cluster, and to gather high level facts from the storage system. The options available are list, show, create, modify and delete. These tasks can be executed by running simple playbooks written in yaml syntax. The modules are written so that all the operations are idempotent, so making multiple identical requests has the same effect as making a single request.

## Table of contents

* [Code of conduct](https://github.com/dell/ansible-powerflex/blob/1.6.0/docs/CODE_OF_CONDUCT.md)
* [Maintainer guide](https://github.com/dell/ansible-powerflex/blob/1.6.0/docs/MAINTAINER_GUIDE.md)
* [Committer guide](https://github.com/dell/ansible-powerflex/blob/1.6.0/docs/COMMITTER_GUIDE.md)
* [Contributing guide](https://github.com/dell/ansible-powerflex/blob/1.6.0/docs/CONTRIBUTING.md)
* [Branching strategy](https://github.com/dell/ansible-powerflex/blob/1.6.0/docs/BRANCHING.md)
* [List of adopters](https://github.com/dell/ansible-powerflex/blob/1.6.0/docs/ADOPTERS.md)
* [Maintainers](https://github.com/dell/ansible-powerflex/blob/1.6.0/docs/MAINTAINERS.md)
* [Support](https://github.com/dell/ansible-powerflex/blob/1.6.0/docs/SUPPORT.md)
* [License](#license)
* [Security](https://github.com/dell/ansible-powerflex/blob/1.6.0/docs/SECURITY.md)
* [Prerequisites](#prerequisites)
* [List of Ansible modules for Dell PowerFlex](#list-of-ansible-modules-for-dell-powerflex)
* [Installation and execution of Ansible modules for Dell PowerFlex](#installation-and-execution-of-ansible-modules-for-dell-powerflex)
* [Releasing, Maintenance and Deprecation](#releasing-maintenance-and-deprecation)

## License
The Ansible collection for PowerFlex is released and licensed under the GPL-3.0 license. See [LICENSE](https://github.com/dell/ansible-powerflex/blob/1.6.0/LICENSE) for the full terms. Ansible modules and modules utilities that are part of the Ansible collection for PowerFlex are released and licensed under the Apache 2.0 license. See [MODULE-LICENSE](https://github.com/dell/ansible-powerflex/blob/1.6.0/MODULE-LICENSE) for the full terms.

## Prerequisites

| **Ansible Modules** | **PowerFlex/VxFlex OS Version** | **SDK version** | **Python version** | **Ansible**              |
|---------------------|-----------------------|-------|--------------------|--------------------------|
| v1.6.0 |3.5 <br> 3.6 <br> 4.0 | 1.7.0 | 3.9.x <br> 3.10.x <br> 3.11.x | 2.12 <br> 2.13 <br> 2.14 |

  * Please follow PyPowerFlex installation instructions on [PyPowerFlex Documentation](https://github.com/dell/python-powerflex)
  
## Idempotency
The modules are written in such a way that all requests are idempotent and hence fault-tolerant. It essentially means that the result of a successfully performed request is independent of the number of times it is executed.

## List of Ansible modules for Dell PowerFlex
  * [Info module](https://github.com/dell/ansible-powerflex/blob/1.6.0/docs/modules/info.rst)
  * [Snapshot module](https://github.com/dell/ansible-powerflex/blob/1.6.0/docs/modules/snapshot.rst)
  * [SDC module](https://github.com/dell/ansible-powerflex/blob/1.6.0/docs/modules/sdc.rst)
  * [Storage pool module](https://github.com/dell/ansible-powerflex/blob/1.6.0/docs/modules/storagepool.rst)
  * [Volume module](https://github.com/dell/ansible-powerflex/blob/1.6.0/docs/modules/volume.rst)
  * [SDS module](https://github.com/dell/ansible-powerflex/blob/1.6.0/docs/modules/sds.rst)
  * [Device Module](https://github.com/dell/ansible-powerflex/blob/1.6.0/docs/modules/device.rst)
  * [Protection Domain Module](https://github.com/dell/ansible-powerflex/blob/1.6.0/docs/modules/protection_domain.rst)
  * [MDM Cluster Module](https://github.com/dell/ansible-powerflex/blob/1.6.0/docs/modules/mdm_cluster.rst)
  * [Replication Consistency Grop Module](https://github.com/dell/ansible-powerflex/blob/1.6.0/docs/modules/replication_consistency_group.rst)
  * [Replication Pair Module](https://github.com/dell/ansible-powerflex/blob/1.6.0/docs/modules/replication_pair.rst)

## Installation and execution of Ansible modules for Dell PowerFlex
The installation and execution steps of Ansible modules for Dell PowerFlex can be found [here](https://github.com/dell/ansible-powerflex/blob/1.6.0/docs/INSTALLATION.md).

## Releasing, Maintenance and Deprecation

Ansible Modules for Dell Technnologies PowerFlex follows [Semantic Versioning](https://semver.org/).

New version will be release regularly if significant changes (bug fix or new feature) are made in the collection.

Released code versions are located on "release" branches with names of the form "release-x.y.z" where x.y.z corresponds to the version number. More information on branching strategy followed can be found [here](https://github.com/dell/ansible-powerflex/blob/1.6.0/docs/BRANCHING.md).

Ansible Modules for Dell Technologies PowerFlex deprecation cycle is aligned with that of [Ansible](https://docs.ansible.com/ansible/latest/dev_guide/module_lifecycle.html).
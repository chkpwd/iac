<a href="https://github.com/Pure-Storage-Ansible/Fusion-Collection/releases/latest"><img src="https://img.shields.io/github/v/tag/Pure-Storage-Ansible/Fusion-Collection?label=release">
<a href="COPYING.GPLv3"><img src="https://img.shields.io/badge/license-GPL%20v3.0-brightgreen.svg"></a>
<img src="https://cla-assistant.io/readme/badge/Pure-Storage-Ansible/Fusion-Collection">
<img src="https://github.com/Pure-Storage-Ansible/Fusion-Collection/workflows/Pure%20Storage%20Ansible%20CI/badge.svg">
<a href="https://github.com/psf/black"><img src="https://img.shields.io/badge/code%20style-black-000000.svg"></a>

# Pure Storage Fusion Collection

The Pure Storage Fusion collection consists of the latest versions of the Fusion modules.

## Requirements

- ansible-core >= 2.11
- Python >= 3.8
- Authorized API Application ID for Pure Storage Pure1 and associated Private Key
  - Refer to Pure Storage documentation on how to create these. 
- purefusion >= 1.0.4
- time

## Available Modules

- fusion_api_client: Manage API clients in Pure Storage Fusion
- fusion_array: Manage arrays in Pure Storage Fusion
- fusion_az: Create Availability Zones in Pure Storage Fusion
- fusion_hap: Manage host access policies in Pure Storage Fusion
- fusion_hw: Create hardware types in Pure Storage Fusion
- fusion_info: Collect information from Pure Fusion
- fusion_ni: Manage Network Interfaces in Pure Storage Fusion
- fusion_nig: Manage Network Interface Groups in Pure Storage Fusion
- fusion_pg: Manage placement groups in Pure Storage Fusion
- fusion_pp: Manage protection policies in Pure Storage Fusion
- fusion_ra: Manage role assignments in Pure Storage Fusion
- fusion_region: Manage regions in Pure Storage Fusion
- fusion_sc: Manage storage classes in Pure Storage Fusion
- fusion_se: Manage storage endpoints in Pure Storage Fusion
- fusion_ss: Manage storage services in Pure Storage Fusion
- fusion_tenant: Manage tenants in Pure Storage Fusion
- fusion_tn: Manage tenant networks in Pure Storage Fusion
- fusion_ts: Manage tenant spaces in Pure Storage Fusion
- fusion_volume: Manage volumes in Pure Storage Fusion

## Instructions

Ansible must be installed [Install guide](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html)
```
sudo pip install ansible
```

Python PureFusion SDK must be installed
```
sudo pip install purefusion
```

Install the Pure Storage Fusion collection on your Ansible management host - [Galaxy link](https://galaxy.ansible.com/purestorage/fusion)
```
ansible-galaxy collection install purestorage.fusion
```

## Example Playbook
```yaml
- hosts: localhost
  tasks:
  - name: Collect information for Pure Storage fleet in Pure1
    purestorage.fusion.fusion_info:
      gather_subset: all
      issuer_id: <Pure1 API Application ID>
      private_key_file: <private key file name>
```

You can find more examples in our [example-playbooks](https://github.com/PureStorage-OpenConnect/ansible-playbook-examples/tree/master/fusion) repository.

## Contributing to this collection

Ongoing development efforts and contributions to this collection are tracked as issues in this repository.

We welcome community contributions to this collection. If you find problems, need an enhancement or need a new module, please open an issue or create a PR against the [Pure Storage Fusion Ansible collection repository](https://github.com/Pure-Storage-Ansible/Fusion-Collection/issues).

Code of Conduct
---------------
This collection follows the Ansible project's
[Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html).
Please read and familiarize yourself with this document.

Releasing, Versioning and Deprecation
-------------------------------------

This collection follows [Semantic Versioning](https://semver.org). More details on versioning can be found [in the Ansible docs](https://docs.ansible.com/ansible/latest/dev_guide/developing_collections.html#collection-versions).

New minor and major releases as well as deprecations will follow new releases and deprecations of the Pure Storage Fusion product, its REST API and the corresponding Python SDK, which this project relies on.

## License

[BSD-2-Clause](https://directory.fsf.org/wiki?title=License:FreeBSD)
[GPL-3.0-or-later](https://www.gnu.org/licenses/gpl-3.0.en.html)

## Author

This collection was created in 2022 by [Simon Dodsley](@sdodsley) for, and on behalf of, the [Pure Storage Ansible Team](pure-ansible-team@purestorage.com)

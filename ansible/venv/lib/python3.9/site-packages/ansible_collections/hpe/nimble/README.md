# HPE Nimble Storage Content Collection for Ansible

## Requirements

- Ansible 2.9 or later
- Python 3.6 or later
- HPE Nimble Storage SDK for Python
- HPE Nimble Storage arrays running NimbleOS 5.0 or later

## Installation

Install the HPE Nimble Storage array collection on your Ansible management host.

```
ansible-galaxy collection install hpe.nimble
```

## Available Modules

- hpe_nimble_access_control_record - Manage the HPE Nimble Storage access control records
- hpe_nimble_array - Manage the HPE Nimble Storage array
- hpe_nimble_chap_user - Manage the HPE Nimble Storage CHAP users
- hpe_nimble_disk - Manage the HPE Nimble Storage disks
- hpe_nimble_encryption - Manage the HPE Nimble Storage encryption
- hpe_nimble_fc - Manage the HPE Nimble Storage fibre channel
- hpe_nimble_group -  Manage the HPE Nimble Storage groups
- hpe_nimble_info - Collect information from HPE Nimble Storage array
- hpe_nimble_initiator_group - Manage the HPE Nimble Storage initiator groups
- hpe_nimble_network - Manage the HPE Nimble Storage network configuration
- hpe_nimble_partner - Manage the HPE Nimble Storage replication partners
- hpe_nimble_performance_policy - Manage the HPE Nimble Storage performance policies
- hpe_nimble_pool - Manage the HPE Nimble Storage pools
- hpe_nimble_protection_schedule - Manage the HPE Nimble Storage protection schedules
- hpe_nimble_protection_template - Manage the HPE Nimble Storage protection templates
- hpe_nimble_shelf - Manage the HPE Nimble Storage shelves
- hpe_nimble_snapshot_collection - Manage the HPE Nimble Storage snapshot collections
- hpe_nimble_snapshot - Manage the HPE Nimble Storage snapshots
- hpe_nimble_user -  Manage the HPE Nimble Storage users
- hpe_nimble_user_policy -  Manage the HPE Nimble Storage user policies
- hpe_nimble_volume -  Manage the HPE Nimble Storage volumes
- hpe_nimble_volume_collection - Manage the HPE Nimble Storage volume collections

## Support

HPE Nimble Storage Content Collection for Ansible is supported by HPE when used with HPE Nimble Storage arrays on valid support contracts. Please send an email to [support@nimblestorage.com](mailto:support@nimblestorage.com) to get started with any issue you might need assistance with. Engage with your HPE representative for other means on how to get in touch with Nimble support directly.

## Releasing, Versioning and Deprecation

This collection follows [Semantic Versioning](https://semver.org/). More details on versioning can be found [in the Ansible docs](https://docs.ansible.com/ansible/latest/dev_guide/developing_collections.html#collection-versions).

We plan to regularly release new minor or bugfix versions once new features or bugfixes have been implemented.

Releasing the current major version happens from the `main` branch. We will create a `stable-1` branch for 1.x.y versions once we start working on a 2.0.0 release, to allow backporting bugfixes and features from the 2.0.0 branch (`main`) to `stable-1`. A `stable-2` branch will be created once we work on a 3.0.0 release, and so on.

We currently are not planning any deprecations or new major releases like 2.0.0 containing backwards incompatible changes. If backwards incompatible changes are needed, we plan to deprecate the old behavior as early as possible. We also plan to backport at least bugfixes for the old major version for some time after releasing a new major version. We will not block community members from backporting other bugfixes and features from the latest stable version to older release branches, under the condition that these backports are of reasonable quality.

## License

HPE Nimble Storage Content Collection for Ansible is released under the GPL-3.0 license.

    Copyright (C) 2021  Hewlett Packard Enterprise Development LP

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

See [LICENSE](https://github.com/hpe-storage/nimble-ansible-modules/blob/master/LICENSE) for the full terms.

The modules interfacing with the array SDKs are released under the Apache-2.0 license.

    Copyright 2020 Hewlett Packard Enterprise Development LP

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

See [MODULE-LICENSE](https://github.com/hpe-storage/nimble-ansible-modules/blob/master/MODULE-LICENSE) for the full terms.

## Code of Conduct

This repository adheres to the [Ansible Community code of conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html)

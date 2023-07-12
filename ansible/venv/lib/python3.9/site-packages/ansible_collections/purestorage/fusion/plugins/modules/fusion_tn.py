#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: fusion_tn
version_added: '1.0.0'
deprecated:
    removed_at_date: "2023-07-26"
    why: Tenant Networks were removed as a concept in Pure Storage Fusion
    alternative: most of the functionality can be replicated using M(purestorage.fusion.fusion_se) and M(purestorage.fusion.fusion_nig)
short_description:  Manage tenant networks in Pure Storage Fusion
description:
- Create or delete tenant networks in Pure Storage Fusion.
notes:
- Supports C(check_mode).
- Currently this only supports a single tenant subnet per tenant network.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - The name of the tenant network.
    type: str
  display_name:
    description:
    - The human name of the tenant network.
    - If not provided, defaults to I(name).
    type: str
  state:
    description:
    - Define whether the tenant network should exist or not.
    type: str
    default: present
    choices: [ absent, present ]
  region:
    description:
    - The name of the region the availability zone is in
    type: str
  availability_zone:
    aliases: [ az ]
    description:
    - The name of the availability zone for the tenant network.
    type: str
  provider_subnets:
    description:
    - List of provider subnets to assign to the tenant networks subnet.
    type: list
    elements: str
  addresses:
    description:
    - List of IP addresses to be used in the subnet of the tenant network.
    - IP addresses must include a CIDR notation.
    - IPv4 and IPv6 are fully supported.
    type: list
    elements: str
  gateway:
    description:
    - Address of the subnet gateway.
    - Currently this must be provided.
    type: str
  mtu:
    description:
    - MTU setting for the subnet.
    default: 1500
    type: int
  prefix:
    description:
    - Network prefix in CIDR format.
    - This will be deprecated soon.
    type: str
extends_documentation_fragment:
- purestorage.fusion.purestorage.fusion
"""

# this module does nothing, thus no example is provided
EXAMPLES = r"""
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.fusion.plugins.module_utils.fusion import (
    fusion_argument_spec,
)


def main():
    """Main code"""
    argument_spec = fusion_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str"),
            region=dict(type="str"),
            display_name=dict(type="str"),
            availability_zone=dict(type="str", aliases=["az"]),
            prefix=dict(type="str"),
            gateway=dict(type="str"),
            mtu=dict(type="int", default=1500),
            provider_subnets=dict(type="list", elements="str"),
            addresses=dict(type="list", elements="str"),
            state=dict(type="str", default="present", choices=["absent", "present"]),
        )
    )
    module = AnsibleModule(argument_spec, supports_check_mode=True)
    module.warn(
        "This module is deprecated, doesn't work, and will be removed in the version 2.0."
        " Please, use purestorage.fusion.fusion_se and purestorage.fusion.fusion_nig instead."
    )
    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

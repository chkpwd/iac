#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: fusion_az
version_added: '1.0.0'
short_description:  Create Availability Zones in Pure Storage Fusion
description:
- Manage an Availability Zone in Pure Storage Fusion.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
notes:
- Supports C(check mode).
options:
  name:
    description:
    - The name of the Availability Zone.
    type: str
    required: true
  state:
    description:
    - Define whether the Availability Zone should exist or not.
    default: present
    choices: [ present, absent ]
    type: str
  display_name:
    description:
    - The human name of the Availability Zone.
    - If not provided, defaults to I(name).
    type: str
  region:
    description:
    - Region within which the AZ is created.
    type: str
    required: true
extends_documentation_fragment:
- purestorage.fusion.purestorage.fusion
"""

EXAMPLES = r"""
- name: Create new AZ foo
  purestorage.fusion.fusion_az:
    name: foo
    display_name: "foo AZ"
    region: region1
    issuer_id: key_name
    private_key_file: "az-admin-private-key.pem"

- name: Delete AZ foo
  purestorage.fusion.fusion_az:
    name: foo
    state: absent
    region: region1
    issuer_id: key_name
    private_key_file: "az-admin-private-key.pem"
"""

RETURN = r"""
"""

try:
    import fusion as purefusion
except ImportError:
    pass

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.fusion.plugins.module_utils.fusion import (
    fusion_argument_spec,
)

from ansible_collections.purestorage.fusion.plugins.module_utils import getters
from ansible_collections.purestorage.fusion.plugins.module_utils.operations import (
    await_operation,
)
from ansible_collections.purestorage.fusion.plugins.module_utils.startup import (
    setup_fusion,
)


def get_az(module, fusion):
    """Get Availability Zone or None"""
    return getters.get_az(module, fusion, availability_zone_name=module.params["name"])


def delete_az(module, fusion):
    """Delete Availability Zone"""

    az_api_instance = purefusion.AvailabilityZonesApi(fusion)

    changed = True
    if not module.check_mode:
        op = az_api_instance.delete_availability_zone(
            region_name=module.params["region"],
            availability_zone_name=module.params["name"],
        )
        await_operation(fusion, op)

    module.exit_json(changed=changed)


def create_az(module, fusion):
    """Create Availability Zone"""

    az_api_instance = purefusion.AvailabilityZonesApi(fusion)

    changed = True
    if not module.check_mode:
        if not module.params["display_name"]:
            display_name = module.params["name"]
        else:
            display_name = module.params["display_name"]

        azone = purefusion.AvailabilityZonePost(
            name=module.params["name"],
            display_name=display_name,
        )
        op = az_api_instance.create_availability_zone(
            azone, region_name=module.params["region"]
        )
        await_operation(fusion, op)

    module.exit_json(changed=changed)


def main():
    """Main code"""
    argument_spec = fusion_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            display_name=dict(type="str"),
            region=dict(type="str", required=True),
            state=dict(type="str", default="present", choices=["present", "absent"]),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)
    fusion = setup_fusion(module)

    state = module.params["state"]
    azone = get_az(module, fusion)

    if not azone and state == "present":
        create_az(module, fusion)
    elif azone and state == "absent":
        delete_az(module, fusion)
    else:
        module.exit_json(changed=False)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

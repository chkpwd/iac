#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: fusion_region
version_added: '1.1.0'
short_description:  Manage Regions in Pure Storage Fusion
description:
- Manage regions in Pure Storage Fusion.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
notes:
- Supports C(check mode).
options:
  name:
    description:
    - The name of the Region.
    type: str
    required: true
  state:
    description:
    - Define whether the Region should exist or not.
    default: present
    choices: [ present, absent ]
    type: str
  display_name:
    description:
    - The human name of the Region.
    - If not provided, defaults to I(name).
    type: str
extends_documentation_fragment:
- purestorage.fusion.purestorage.fusion
"""

EXAMPLES = r"""
- name: Create new region foo
  purestorage.fusion.fusion_region:
    name: foo
    display_name: "foo Region"
    issuer_id: key_name
    private_key_file: "az-admin-private-key.pem"

- name: Update region foo
  purestorage.fusion.fusion_region:
    name: foo
    display_name: "new foo Region"
    issuer_id: key_name
    private_key_file: "az-admin-private-key.pem"

- name: Delete region foo
  purestorage.fusion.fusion_region:
    name: foo
    state: absent
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

from ansible_collections.purestorage.fusion.plugins.module_utils.operations import (
    await_operation,
)
from ansible_collections.purestorage.fusion.plugins.module_utils.startup import (
    setup_fusion,
)
from ansible_collections.purestorage.fusion.plugins.module_utils import getters


def get_region(module, fusion):
    """Get Region or None"""
    return getters.get_region(module, fusion, module.params["name"])


def create_region(module, fusion):
    """Create Region"""

    reg_api_instance = purefusion.RegionsApi(fusion)

    changed = True
    if not module.check_mode:
        if not module.params["display_name"]:
            display_name = module.params["name"]
        else:
            display_name = module.params["display_name"]
        region = purefusion.RegionPost(
            name=module.params["name"],
            display_name=display_name,
        )
        op = reg_api_instance.create_region(region)
        await_operation(fusion, op)

    module.exit_json(changed=changed)


def delete_region(module, fusion):
    """Delete Region"""

    reg_api_instance = purefusion.RegionsApi(fusion)

    changed = True
    if not module.check_mode:
        op = reg_api_instance.delete_region(region_name=module.params["name"])
        await_operation(fusion, op)

    module.exit_json(changed=changed)


def update_region(module, fusion, region):
    """Update Region settings"""
    changed = False
    reg_api_instance = purefusion.RegionsApi(fusion)

    if (
        module.params["display_name"]
        and module.params["display_name"] != region.display_name
    ):
        changed = True
        if not module.check_mode:
            reg = purefusion.RegionPatch(
                display_name=purefusion.NullableString(module.params["display_name"])
            )
            op = reg_api_instance.update_region(
                reg,
                region_name=module.params["name"],
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
            state=dict(type="str", default="present", choices=["present", "absent"]),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)
    fusion = setup_fusion(module)

    state = module.params["state"]
    region = get_region(module, fusion)

    if not region and state == "present":
        create_region(module, fusion)
    elif region and state == "present":
        update_region(module, fusion, region)
    elif region and state == "absent":
        delete_region(module, fusion)
    else:
        module.exit_json(changed=False)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

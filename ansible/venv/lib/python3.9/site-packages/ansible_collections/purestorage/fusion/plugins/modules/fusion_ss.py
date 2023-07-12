#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: fusion_ss
version_added: '1.0.0'
short_description:  Manage storage services in Pure Storage Fusion
description:
- Manage a storage services in Pure Storage Fusion.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
notes:
- Supports C(check mode).
options:
  name:
    description:
    - The name of the storage service.
    type: str
    required: true
  state:
    description:
    - Define whether the storage service should exist or not.
    default: present
    choices: [ present, absent ]
    type: str
  display_name:
    description:
    - The human name of the storage service.
    - If not provided, defaults to I(name).
    type: str
  hardware_types:
    description:
    - Hardware types to which the storage service applies.
    type: list
    elements: str
    choices: [ flash-array-x, flash-array-c, flash-array-x-optane, flash-array-xl ]
extends_documentation_fragment:
- purestorage.fusion.purestorage.fusion
"""

EXAMPLES = r"""
- name: Create new storage service foo
  purestorage.fusion.fusion_ss:
    name: foo
    hardware_types:
    - flash-array-x
    - flash-array-x-optane
    display_name: "test class"
    issuer_id: key_name
    private_key_file: "az-admin-private-key.pem"

- name: Update storage service
  purestorage.fusion.fusion_ss:
    name: foo
    display_name: "main class"
    hardware_types:
    - flash-array-c
    issuer_id: key_name
    private_key_file: "az-admin-private-key.pem"

- name: Delete storage service
  purestorage.fusion.fusion_ss:
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
from ansible_collections.purestorage.fusion.plugins.module_utils.startup import (
    setup_fusion,
)
from ansible_collections.purestorage.fusion.plugins.module_utils import getters
from ansible_collections.purestorage.fusion.plugins.module_utils.operations import (
    await_operation,
)


def get_ss(module, fusion):
    """Return Storage Service or None"""
    return getters.get_ss(module, fusion, storage_service_name=module.params["name"])


def create_ss(module, fusion):
    """Create Storage Service"""

    ss_api_instance = purefusion.StorageServicesApi(fusion)

    changed = True
    if not module.check_mode:
        if not module.params["display_name"]:
            display_name = module.params["name"]
        else:
            display_name = module.params["display_name"]
        s_service = purefusion.StorageServicePost(
            name=module.params["name"],
            display_name=display_name,
            hardware_types=module.params["hardware_types"],
        )
        op = ss_api_instance.create_storage_service(s_service)
        await_operation(fusion, op)

    module.exit_json(changed=changed)


def delete_ss(module, fusion):
    """Delete Storage Service"""

    ss_api_instance = purefusion.StorageServicesApi(fusion)

    changed = True
    if not module.check_mode:
        op = ss_api_instance.delete_storage_service(
            storage_service_name=module.params["name"]
        )
        await_operation(fusion, op)

    module.exit_json(changed=changed)


def update_ss(module, fusion, ss):
    """Update Storage Service"""

    ss_api_instance = purefusion.StorageServicesApi(fusion)
    patches = []
    if (
        module.params["display_name"]
        and module.params["display_name"] != ss.display_name
    ):
        patch = purefusion.StorageServicePatch(
            display_name=purefusion.NullableString(module.params["display_name"]),
        )
        patches.append(patch)

    if not module.check_mode:
        for patch in patches:
            op = ss_api_instance.update_storage_service(
                patch,
                storage_service_name=module.params["name"],
            )
            await_operation(fusion, op)

    changed = len(patches) != 0

    module.exit_json(changed=changed)


def main():
    """Main code"""
    argument_spec = fusion_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            display_name=dict(type="str"),
            hardware_types=dict(
                type="list",
                elements="str",
                choices=[
                    "flash-array-x",
                    "flash-array-c",
                    "flash-array-x-optane",
                    "flash-array-xl",
                ],
            ),
            state=dict(type="str", default="present", choices=["present", "absent"]),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)
    fusion = setup_fusion(module)

    state = module.params["state"]
    s_service = get_ss(module, fusion)

    if not s_service and state == "present":
        module.fail_on_missing_params(["hardware_types"])
        create_ss(module, fusion)
    elif s_service and state == "present":
        update_ss(module, fusion, s_service)
    elif s_service and state == "absent":
        delete_ss(module, fusion)
    else:
        module.exit_json(changed=False)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

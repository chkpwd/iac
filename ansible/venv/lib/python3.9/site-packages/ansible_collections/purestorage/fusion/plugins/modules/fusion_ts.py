#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: fusion_ts
version_added: '1.0.0'
short_description:  Manage tenant spaces in Pure Storage Fusion
description:
- Create, update or delete a tenant spaces in Pure Storage Fusion.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
notes:
- Supports C(check mode).
options:
  name:
    description:
    - The name of the tenant space.
    type: str
    required: true
  display_name:
    description:
    - The human name of the tenant space.
    - If not provided, defaults to I(name).
    type: str
  state:
    description:
    - Define whether the tenant space should exist or not.
    type: str
    default: present
    choices: [ absent, present ]
  tenant:
    description:
    - The name of the tenant.
    type: str
    required: true
extends_documentation_fragment:
- purestorage.fusion.purestorage.fusion
"""

EXAMPLES = r"""
- name: Create new tenant space foo for tenant bar
  purestorage.fusion.fusion_ts:
    name: foo
    tenant: bar
    state: present
    issuer_id: key_name
    private_key_file: "az-admin-private-key.pem"

- name: Delete tenant space foo in tenant bar
  purestorage.fusion.fusion_ts:
    name: foo
    tenant: bar
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


def get_ts(module, fusion):
    """Tenant Space or None"""
    return getters.get_ts(module, fusion, tenant_space_name=module.params["name"])


def create_ts(module, fusion):
    """Create Tenant Space"""

    ts_api_instance = purefusion.TenantSpacesApi(fusion)

    changed = True
    if not module.check_mode:
        if not module.params["display_name"]:
            display_name = module.params["name"]
        else:
            display_name = module.params["display_name"]
        tspace = purefusion.TenantSpacePost(
            name=module.params["name"],
            display_name=display_name,
        )
        op = ts_api_instance.create_tenant_space(
            tspace,
            tenant_name=module.params["tenant"],
        )
        await_operation(fusion, op)

    module.exit_json(changed=changed)


def update_ts(module, fusion, ts):
    """Update Tenant Space"""

    ts_api_instance = purefusion.TenantSpacesApi(fusion)
    patches = []
    if (
        module.params["display_name"]
        and module.params["display_name"] != ts.display_name
    ):
        patch = purefusion.TenantSpacePatch(
            display_name=purefusion.NullableString(module.params["display_name"]),
        )
        patches.append(patch)

    if not module.check_mode:
        for patch in patches:
            op = ts_api_instance.update_tenant_space(
                patch,
                tenant_name=module.params["tenant"],
                tenant_space_name=module.params["name"],
            )
            await_operation(fusion, op)

    changed = len(patches) != 0

    module.exit_json(changed=changed)


def delete_ts(module, fusion):
    """Delete Tenant Space"""
    changed = True
    ts_api_instance = purefusion.TenantSpacesApi(fusion)
    if not module.check_mode:
        op = ts_api_instance.delete_tenant_space(
            tenant_name=module.params["tenant"],
            tenant_space_name=module.params["name"],
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
            tenant=dict(type="str", required=True),
            state=dict(type="str", default="present", choices=["absent", "present"]),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)
    fusion = setup_fusion(module)

    state = module.params["state"]
    tspace = get_ts(module, fusion)

    if state == "present" and not tspace:
        create_ts(module, fusion)
    elif state == "present" and tspace:
        update_ts(module, fusion, tspace)
    elif state == "absent" and tspace:
        delete_ts(module, fusion)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

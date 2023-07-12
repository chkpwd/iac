#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: fusion_tenant
version_added: '1.0.0'
short_description:  Manage tenants in Pure Storage Fusion
description:
- Create,delete or update a tenant in Pure Storage Fusion.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
notes:
- Supports C(check mode).
options:
  name:
    description:
    - The name of the tenant.
    type: str
    required: true
  state:
    description:
    - Define whether the tenant should exist or not.
    default: present
    choices: [ present, absent ]
    type: str
  display_name:
    description:
    - The human name of the tenant.
    - If not provided, defaults to I(name).
    type: str
extends_documentation_fragment:
- purestorage.fusion.purestorage.fusion
"""

EXAMPLES = r"""
- name: Create new tenat foo
  purestorage.fusion.fusion_tenant:
    name: foo
    display_name: "tenant foo"
    issuer_id: key_name
    private_key_file: "az-admin-private-key.pem"

- name: Delete tenat foo
  purestorage.fusion.fusion_tenant:
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


def get_tenant(module, fusion):
    """Return Tenant or None"""
    return getters.get_tenant(module, fusion, tenant_name=module.params["name"])


def create_tenant(module, fusion):
    """Create Tenant"""

    api_instance = purefusion.TenantsApi(fusion)
    changed = True
    if not module.check_mode:
        if not module.params["display_name"]:
            display_name = module.params["name"]
        else:
            display_name = module.params["display_name"]
        tenant = purefusion.TenantPost(
            name=module.params["name"],
            display_name=display_name,
        )
        op = api_instance.create_tenant(tenant)
        await_operation(fusion, op)

    module.exit_json(changed=changed)


def update_tenant(module, fusion, tenant):
    """Update Tenant settings"""
    changed = False
    api_instance = purefusion.TenantsApi(fusion)

    if (
        module.params["display_name"]
        and module.params["display_name"] != tenant.display_name
    ):
        changed = True
        if not module.check_mode:
            new_tenant = purefusion.TenantPatch(
                display_name=purefusion.NullableString(module.params["display_name"]),
            )
            op = api_instance.update_tenant(
                new_tenant,
                tenant_name=module.params["name"],
            )
            await_operation(fusion, op)

    module.exit_json(changed=changed)


def delete_tenant(module, fusion):
    """Delete Tenant"""
    changed = True
    api_instance = purefusion.TenantsApi(fusion)
    if not module.check_mode:
        op = api_instance.delete_tenant(tenant_name=module.params["name"])
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
    tenant = get_tenant(module, fusion)

    if not tenant and state == "present":
        create_tenant(module, fusion)
    elif tenant and state == "present":
        update_tenant(module, fusion, tenant)
    elif tenant and state == "absent":
        delete_tenant(module, fusion)
    else:
        module.exit_json(changed=False)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

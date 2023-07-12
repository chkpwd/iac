#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: fusion_ra
version_added: '1.0.0'
short_description:  Manage role assignments in Pure Storage Fusion
description:
- Create or delete a storage class in Pure Storage Fusion.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
notes:
- Supports C(check mode).
options:
  role:
    description:
    - The name of the role to be assigned/unassigned.
    type: str
    required: true
  state:
    description:
    - Define whether the role assingment should exist or not.
    type: str
    default: present
    choices: [ absent, present ]
  user:
    description:
    - The username to assign the role to.
    - Currently this only supports the Pure1 App ID.
    - This should be provide in the same format as I(issuer_id).
    type: str
  principal:
    description:
    - The unique ID of the principal (User or API Client) to assign to the role.
    type: str
  api_client_key:
    description:
    - The key of API client to assign the role to.
    type: str
  scope:
    description:
    - The level to which the role is assigned.
    choices: [ organization, tenant, tenant_space ]
    default: organization
    type: str
  tenant:
    description:
    - The name of the tenant the user has the role applied to.
    - Must be provided if I(scope) is set to either C(tenant) or C(tenant_space).
    type: str
  tenant_space:
    description:
    - The name of the tenant_space the user has the role applied to.
    - Must be provided if I(scope) is set to C(tenant_space).
    type: str
extends_documentation_fragment:
- purestorage.fusion.purestorage.fusion
"""

EXAMPLES = r"""
- name: Assign role foo to user in tenant bar
  purestorage.fusion.fusion_ra:
    name: foo
    user: key_name
    tenant: bar
    issuer_id: key_name
    private_key_file: "az-admin-private-key.pem"

- name: Delete role foo from user in tenant bar
  purestorage.fusion.fusion_ra:
    name: foo
    user: key_name
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

from ansible_collections.purestorage.fusion.plugins.module_utils.operations import (
    await_operation,
)
from ansible_collections.purestorage.fusion.plugins.module_utils.startup import (
    setup_fusion,
)


def get_principal(module, fusion):
    if module.params["principal"]:
        return module.params["principal"]
    if module.params["user"]:
        principal = user_to_principal(fusion, module.params["user"])
        if not principal:
            module.fail_json(
                msg="User {0} does not exist".format(module.params["user"])
            )
        return principal
    if module.params["api_client_key"]:
        principal = apiclient_to_principal(fusion, module.params["api_client_key"])
        if not principal:
            module.fail_json(
                msg="API Client with key {0} does not exist".format(
                    module.params["api_client_key"]
                )
            )
        return principal


def user_to_principal(fusion, user_id):
    """Given a human readable Fusion user, such as a Pure 1 App ID
    return the associated principal
    """
    id_api_instance = purefusion.IdentityManagerApi(fusion)
    users = id_api_instance.list_users()
    for user in users:
        if user.name == user_id:
            return user.id
    return None


def apiclient_to_principal(fusion, api_client_key):
    """Given an API client key, such as "pure1:apikey:123xXxyYyzYzASDF" (also known as issuer_id),
    return the associated principal
    """
    id_api_instance = purefusion.IdentityManagerApi(fusion)
    api_clients = id_api_instance.list_users(name=api_client_key)
    if len(api_clients) > 0:
        return api_clients[0].id
    return None


def get_scope(params):
    """Given a scope type and associated tenant
    and tenant_space, return the scope_link
    """
    scope_link = None
    if params["scope"] == "organization":
        scope_link = "/"
    elif params["scope"] == "tenant":
        scope_link = "/tenants/" + params["tenant"]
    elif params["scope"] == "tenant_space":
        scope_link = (
            "/tenants/" + params["tenant"] + "/tenant-spaces/" + params["tenant_space"]
        )
    return scope_link


def get_ra(module, fusion):
    """Return Role Assignment or None"""
    ra_api_instance = purefusion.RoleAssignmentsApi(fusion)
    try:
        principal = get_principal(module, fusion)
        assignments = ra_api_instance.list_role_assignments(
            role_name=module.params["role"],
            principal=principal,
        )
        for assign in assignments:
            scope = get_scope(module.params)
            if assign.scope.self_link == scope:
                return assign
        return None
    except purefusion.rest.ApiException:
        return None


def create_ra(module, fusion):
    """Create Role Assignment"""

    ra_api_instance = purefusion.RoleAssignmentsApi(fusion)

    changed = True
    if not module.check_mode:
        principal = get_principal(module, fusion)
        scope = get_scope(module.params)
        assignment = purefusion.RoleAssignmentPost(scope=scope, principal=principal)
        op = ra_api_instance.create_role_assignment(
            assignment, role_name=module.params["role"]
        )
        await_operation(fusion, op)
    module.exit_json(changed=changed)


def delete_ra(module, fusion):
    """Delete Role Assignment"""
    changed = True
    ra_api_instance = purefusion.RoleAssignmentsApi(fusion)
    if not module.check_mode:
        ra_name = get_ra(module, fusion).name
        op = ra_api_instance.delete_role_assignment(
            role_name=module.params["role"], role_assignment_name=ra_name
        )
        await_operation(fusion, op)

    module.exit_json(changed=changed)


def main():
    """Main code"""
    argument_spec = fusion_argument_spec()
    argument_spec.update(
        dict(
            api_client_key=dict(type="str", no_log=True),
            principal=dict(type="str"),
            role=dict(
                type="str",
                required=True,
                deprecated_aliases=[
                    dict(
                        name="name",
                        date="2023-07-26",
                        collection_name="purefusion.fusion",
                    )
                ],
            ),
            scope=dict(
                type="str",
                default="organization",
                choices=["organization", "tenant", "tenant_space"],
            ),
            state=dict(type="str", default="present", choices=["present", "absent"]),
            tenant=dict(type="str"),
            tenant_space=dict(type="str"),
            user=dict(type="str"),
        )
    )

    required_if = [
        ["scope", "tenant", ["tenant"]],
        ["scope", "tenant_space", ["tenant", "tenant_space"]],
    ]
    mutually_exclusive = [
        ("user", "principal", "api_client_key"),
    ]
    required_one_of = [
        ("user", "principal", "api_client_key"),
    ]

    module = AnsibleModule(
        argument_spec,
        required_if=required_if,
        supports_check_mode=True,
        mutually_exclusive=mutually_exclusive,
        required_one_of=required_one_of,
    )
    fusion = setup_fusion(module)

    state = module.params["state"]
    role_assignment = get_ra(module, fusion)

    if not role_assignment and state == "present":
        create_ra(module, fusion)
    elif role_assignment and state == "absent":
        delete_ra(module, fusion)
    else:
        module.exit_json(changed=False)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

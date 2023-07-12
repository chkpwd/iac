#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2019, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: purefa_dsrole
version_added: '1.0.0'
short_description: Configure FlashArray Directory Service Roles
description:
- Set or erase directory services role configurations.
- Only available for FlashArray running Purity 5.2.0 or higher
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Create or delete directory service role
    type: str
    default: present
    choices: [ absent, present ]
  role:
    description:
    - The directory service role to work on
    type: str
    required: true
    choices: [ array_admin, ops_admin, readonly, storage_admin ]
  group_base:
    type: str
    description:
    - Specifies where the configured group is located in the directory
      tree. This field consists of Organizational Units (OUs) that combine
      with the base DN attribute and the configured group CNs to complete
      the full Distinguished Name of the groups. The group base should
      specify OU= for each OU and multiple OUs should be separated by commas.
      The order of OUs is important and should get larger in scope from left
      to right.
    - Each OU should not exceed 64 characters in length.
  group:
    type: str
    description:
    - Sets the common Name (CN) of the configured directory service group
      containing users for the FlashBlade. This name should be just the
      Common Name of the group without the CN= specifier.
    - Common Names should not exceed 64 characters in length.
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Delete exisitng array_admin directory service role
  purestorage.flasharray.purefa_dsrole:
    role: array_admin
    state: absent
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Create array_admin directory service role
  purestorage.flasharray.purefa_dsrole:
    role: array_admin
    group_base: "OU=PureGroups,OU=SANManagers"
    group: pureadmins
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Update ops_admin directory service role
  purestorage.flasharray.purefa_dsrole:
    role: ops_admin
    group_base: "OU=PureGroups"
    group: opsgroup
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_system,
    purefa_argument_spec,
)


def update_role(module, array):
    """Update Directory Service Role"""
    changed = False
    role = array.list_directory_service_roles(names=[module.params["role"]])
    if (
        role[0]["group_base"] != module.params["group_base"]
        or role[0]["group"] != module.params["group"]
    ):
        try:
            changed = True
            if not module.check_mode:
                array.set_directory_service_roles(
                    names=[module.params["role"]],
                    group_base=module.params["group_base"],
                    group=module.params["group"],
                )
        except Exception:
            module.fail_json(
                msg="Update Directory Service Role {0} failed".format(
                    module.params["role"]
                )
            )
    module.exit_json(changed=changed)


def delete_role(module, array):
    """Delete Directory Service Role"""
    changed = True
    if not module.check_mode:
        try:
            array.set_directory_service_roles(
                names=[module.params["role"]], group_base="", group=""
            )
        except Exception:
            module.fail_json(
                msg="Delete Directory Service Role {0} failed".format(
                    module.params["role"]
                )
            )
    module.exit_json(changed=changed)


def create_role(module, array):
    """Create Directory Service Role"""
    changed = False
    if not module.params["group"] == "" or not module.params["group_base"] == "":
        changed = True
        if not module.check_mode:
            try:
                array.set_directory_service_roles(
                    names=[module.params["role"]],
                    group_base=module.params["group_base"],
                    group=module.params["group"],
                )
            except Exception:
                module.fail_json(
                    msg="Create Directory Service Role {0} failed".format(
                        module.params["role"]
                    )
                )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            role=dict(
                required=True,
                type="str",
                choices=["array_admin", "ops_admin", "readonly", "storage_admin"],
            ),
            state=dict(type="str", default="present", choices=["absent", "present"]),
            group_base=dict(type="str"),
            group=dict(type="str"),
        )
    )

    required_together = [["group", "group_base"]]

    module = AnsibleModule(
        argument_spec, required_together=required_together, supports_check_mode=True
    )

    state = module.params["state"]
    array = get_system(module)
    role_configured = False
    role = array.list_directory_service_roles(names=[module.params["role"]])
    if role[0]["group"] is not None:
        role_configured = True

    if state == "absent" and role_configured:
        delete_role(module, array)
    elif role_configured and state == "present":
        update_role(module, array)
    elif not role_configured and state == "present":
        create_role(module, array)
    else:
        module.exit_json(changed=False)


if __name__ == "__main__":
    main()

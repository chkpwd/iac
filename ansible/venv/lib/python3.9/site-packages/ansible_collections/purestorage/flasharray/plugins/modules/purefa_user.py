#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2018, Simon Dodsley (simon@purestorage.com)
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
module: purefa_user
version_added: '1.0.0'
short_description: Create, modify or delete FlashArray local user account
description:
- Create, modify or delete local users on a Pure Stoage FlashArray.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Create, delete or update local user account
    default: present
    type: str
    choices: [ absent, present ]
  name:
    description:
    - The name of the local user account
    type: str
    required: true
  role:
    description:
    - Sets the local user's access level to the array
    type: str
    choices: [ readonly, ops_admin, storage_admin, array_admin ]
  password:
    description:
    - Password for the local user.
    type: str
  old_password:
    description:
    - If changing an existing password, you must provide the old password for security
    type: str
  api:
    description:
    - Define whether to create an API token for this user
    - Token can be exposed using the I(debug) module
    type: bool
    default: false
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Create new user ansible with API token
  purestorage.flasharray.purefa_user:
    name: ansible
    password: apassword
    role: storage_admin
    api: true
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
  register: result

  debug:
    msg: "API Token: {{ result['user_info']['user_api'] }}"

- name: Change role type for existing user
  purestorage.flasharray.purefa_user:
    name: ansible
    role: array_admin
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Change password type for existing user (NOT IDEMPOTENT)
  purestorage.flasharray.purefa_user:
    name: ansible
    password: anewpassword
    old_password: apassword
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Change API token for existing user
  purestorage.flasharray.purefa_user:
    name: ansible
    api: true
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
  register: result

  debug:
    msg: "API Token: {{ result['user_info']['user_api'] }}"
"""

RETURN = r"""
"""


import re
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_system,
    purefa_argument_spec,
)

MIN_REQUIRED_API_VERSION = "1.14"


def get_user(module, array):
    """Return Local User Account or None"""
    user = None
    users = array.list_admins()
    for acct in range(0, len(users)):
        if users[acct]["name"] == module.params["name"]:
            user = users[acct]
    return user


def create_user(module, array):
    """Create or Update Local User Account"""
    changed = api_changed = role_changed = passwd_changed = False
    user = get_user(module, array)
    role = module.params["role"]
    user_token = {}
    if not user:
        changed = True
        if not module.check_mode:
            try:
                if not role:
                    role = "readonly"
                array.create_admin(
                    module.params["name"], role=role, password=module.params["password"]
                )
                if module.params["api"]:
                    try:
                        user_token["user_api"] = array.create_api_token(
                            module.params["name"]
                        )["api_token"]
                    except Exception:
                        array.delete_user(module.params["name"])
                        module.fail_json(
                            msg="Local User {0}: Creation failed".format(
                                module.params["name"]
                            )
                        )
            except Exception:
                module.fail_json(
                    msg="Local User {0}: Creation failed".format(module.params["name"])
                )
    else:
        if module.params["password"] and not module.params["old_password"]:
            module.exit_json(changed=changed)
        if module.params["password"] and module.params["old_password"]:
            if module.params["old_password"] and (
                module.params["password"] != module.params["old_password"]
            ):
                passwd_changed = True
                if not module.check_mode:
                    try:
                        array.set_admin(
                            module.params["name"],
                            password=module.params["password"],
                            old_password=module.params["old_password"],
                        )
                    except Exception:
                        module.fail_json(
                            msg="Local User {0}: Password reset failed. "
                            "Check old password.".format(module.params["name"])
                        )
            else:
                module.fail_json(
                    msg="Local User Account {0}: Password change failed - "
                    "Check both old and new passwords".format(module.params["name"])
                )
        if module.params["api"]:
            try:
                if not array.get_api_token(module.params["name"])["api_token"] is None:
                    if not module.check_mode:
                        array.delete_api_token(module.params["name"])
                api_changed = True
                if not module.check_mode:
                    user_token["user_api"] = array.create_api_token(
                        module.params["name"]
                    )["api_token"]
            except Exception:
                module.fail_json(
                    msg="Local User {0}: API token change failed".format(
                        module.params["name"]
                    )
                )
        if module.params["role"] and module.params["role"] != user["role"]:
            if module.params["name"] != "pureuser":
                role_changed = True
                if not module.check_mode:
                    try:
                        array.set_admin(
                            module.params["name"], role=module.params["role"]
                        )
                    except Exception:
                        module.fail_json(
                            msg="Local User {0}: Role changed failed".format(
                                module.params["name"]
                            )
                        )
            else:
                module.warn("Role for 'pureuser' cannot be modified.")
        changed = bool(passwd_changed or role_changed or api_changed)
    module.exit_json(changed=changed, user_info=user_token)


def delete_user(module, array):
    """Delete Local User Account"""
    changed = False
    if get_user(module, array):
        changed = True
        if not module.check_mode:
            try:
                array.delete_admin(module.params["name"])
            except Exception:
                module.fail_json(
                    msg="Object Store Account {0}: Deletion failed".format(
                        module.params["name"]
                    )
                )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            name=dict(required=True, type="str"),
            role=dict(
                type="str",
                choices=["readonly", "ops_admin", "storage_admin", "array_admin"],
            ),
            state=dict(type="str", default="present", choices=["absent", "present"]),
            password=dict(type="str", no_log=True),
            old_password=dict(type="str", no_log=True),
            api=dict(type="bool", default=False),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    state = module.params["state"]
    array = get_system(module)
    api_version = array._list_available_rest_versions()

    if MIN_REQUIRED_API_VERSION not in api_version:
        module.fail_json(
            msg="FlashArray REST version not supported. "
            "Minimum version required: {0}".format(MIN_REQUIRED_API_VERSION)
        )
    pattern = re.compile("^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$")
    if not pattern.match(module.params["name"]):
        module.fail_json(
            msg="name must contain a minimum of 1 and a maximum of 32 characters "
            "(alphanumeric or `-`). All letters must be lowercase."
        )

    if state == "absent":
        delete_user(module, array)
    elif state == "present":
        create_user(module, array)
    else:
        module.exit_json(changed=False)


if __name__ == "__main__":
    main()

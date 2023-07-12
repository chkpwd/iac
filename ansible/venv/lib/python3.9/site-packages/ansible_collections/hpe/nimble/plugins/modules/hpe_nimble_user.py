#!/usr/bin/python

# # Copyright 2020 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
# file except in compliance with the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
# OF ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.

# author Alok Ranjan (alok.ranjan2@hpe.com)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
author:
  - HPE Nimble Storage Ansible Team (@ar-india) <nimble-dcs-storage-automation-eng@hpe.com>
description: Manage the users on an HPE Nimble Storage group.
module: hpe_nimble_user
options:
  auth_password:
    required: False
    type: str
    description:
    - Authorization password for changing password.
  change_name:
    required: False
    type: str
    description:
    - Change name of the existing user.
  description:
    required: False
    type: str
    description:
    - Description of the user.
  disabled:
    required: False
    type: bool
    description:
    - User is currently disabled.
  email_addr:
    required: False
    type: str
    description:
    - Email address of the user.
  full_name:
    required: False
    type: str
    description:
    - Fully qualified name of the user.
  inactivity_timeout:
    required: False
    type: int
    default: 0
    description:
    - The amount of time that the user session is inactive before timing out. A value of 0 indicates that the timeout is taken from the group setting.
  name:
    required: True
    type: str
    description:
    - Name of the user.
  user_password:
    required: False
    type: str
    description:
    - User's login password.
  role:
    required: False
    choices:
    - administrator
    - poweruser
    - operator
    - guest
    type: str
    description:
    - Role of the user. Default is 'guest'.
  state:
    required: True
    choices:
    -  create
    -  present
    -  absent
    type: str
    description:
    - The user operation.
  unlock:
    required: False
    type: bool
    description:
    - Unlock the user.
extends_documentation_fragment: hpe.nimble.hpe_nimble
short_description: Manage the HPE Nimble Storage users
version_added: "1.0.0"
notes:
  - This module does not support C(check_mode).
'''

EXAMPLES = r'''

# if state is create, then create user, fails if it exist or cannot create
# if state is present, then create user if not present, else success
- name: Create user
  hpe.nimble.hpe_nimble_user:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "{{ name }}"
    description: "{{ description }}"
    state: "{{ state | default('present') }}"

- name: Delete user
  hpe.nimble.hpe_nimble_user:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "{{ name }}"
    state: "absent"

- name: Unlock user
  hpe.nimble.hpe_nimble_user:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "{{ name }}"
    state: "present"
    unlock: true

'''
RETURN = r'''
'''

from ansible.module_utils.basic import AnsibleModule
try:
    from nimbleclient.v1 import client
except ImportError:
    client = None
from ansible_collections.hpe.nimble.plugins.module_utils.hpe_nimble import __version__ as NIMBLE_ANSIBLE_VERSION
import ansible_collections.hpe.nimble.plugins.module_utils.hpe_nimble as utils


def create_user(
        client_obj,
        user_name,
        password,
        **kwargs):

    if utils.is_null_or_empty(user_name):
        return (False, False, "Create user failed as user is not present.", {}, {})
    if utils.is_null_or_empty(password):
        return (False, False, "Create user failed as password is not present.", {}, {})

    try:
        user_resp = client_obj.users.get(id=None, name=user_name)
        if utils.is_null_or_empty(user_resp):
            params = utils.remove_null_args(**kwargs)
            user_resp = client_obj.users.create(name=user_name, password=password, **params)
            return (True, True, f"User '{user_name}' created successfully.", {}, user_resp.attrs)
        else:
            return (False, False, f"User '{user_name}' cannot be created as it is already present in given state.", {}, {})
    except Exception as ex:
        return (False, False, f"User creation failed | {ex}", {}, {})


def update_user(
        client_obj,
        user_name,
        **kwargs):

    if utils.is_null_or_empty(user_name):
        return (False, False, "Update user failed as user is not present.", {}, {})

    try:
        user_resp = client_obj.users.get(id=None, name=user_name)
        if utils.is_null_or_empty(user_resp):
            return (False, False, f"User '{user_name}' cannot be updated as it is not present.", {}, {})

        changed_attrs_dict, params = utils.remove_unchanged_or_null_args(user_resp, **kwargs)
        if changed_attrs_dict.__len__() > 0:
            user_resp = client_obj.users.update(id=user_resp.attrs.get("id"), **params)
            return (True, True, f"User '{user_name}' already present. Modified the following attributes '{changed_attrs_dict}'",
                    changed_attrs_dict, user_resp.attrs)
        else:
            return (True, False, f"User '{user_resp.attrs.get('name')}' already present in given state.", {}, user_resp.attrs)
    except Exception as ex:
        return (False, False, f"User update failed | {ex}", {}, {})


def delete_user(
        client_obj,
        user_name):

    if utils.is_null_or_empty(user_name):
        return (False, False, "Delete user failed as user is not present.", {})

    try:
        user_resp = client_obj.users.get(id=None, name=user_name)
        if utils.is_null_or_empty(user_resp):
            return (False, False, f"User '{user_name}' cannot be deleted as it is not present.", {})

        client_obj.users.delete(id=user_resp.attrs.get("id"))
        return (True, True, f"Deleted user '{user_name}' successfully.", {})
    except Exception as ex:
        return (False, False, f"Delete user failed | {ex}", {})


def unlock_user(
        client_obj,
        user_name):

    if utils.is_null_or_empty(user_name):
        return (False, False, "Unlock user failed as user name is not present.", {})

    try:
        user_resp = client_obj.users.get(id=None, name=user_name)
        if utils.is_null_or_empty(user_resp):
            return (False, False, f"User '{user_name}' cannot be unlocked as it is not present.", {})

        client_obj.users.unlock(id=user_resp.attrs.get("id"))
        return (True, True, f"Unlocked user '{user_name}' successfully.", {})
    except Exception as ex:
        return (False, False, f"Unlock user failed | {ex}", {})


def main():

    fields = {
        "state": {
            "required": True,
            "choices": ['create',
                        'present',
                        'absent'
                        ],
            "type": "str"
        },
        "change_name": {
            "required": False,
            "type": "str"
        },
        "name": {
            "required": True,
            "type": "str"
        },
        "description": {
            "required": False,
            "type": "str"
        },
        "role": {
            "required": False,
            "choices": ['administrator',
                        'poweruser',
                        'operator',
                        'guest'
                        ],
            "type": "str"
        },
        "user_password": {
            "required": False,
            "type": "str",
            "no_log": True
        },
        "inactivity_timeout": {
            "required": False,
            "type": "int"
        },
        "full_name": {
            "required": False,
            "type": "str"
        },
        "email_addr": {
            "required": False,
            "type": "str"
        },
        "disabled": {
            "required": False,
            "type": "bool"
        },
        "auth_password": {
            "required": False,
            "type": "str",
            "no_log": True
        },
        "unlock": {
            "required": False,
            "type": "bool"
        }
    }
    default_fields = utils.basic_auth_arg_fields()
    fields.update(default_fields)
    required_if = [('state', 'create', ['user_password'])]

    module = AnsibleModule(argument_spec=fields, required_if=required_if)
    if client is None:
        module.fail_json(msg='Python nimble-sdk could not be found.')

    hostname = module.params["host"]
    username = module.params["username"]
    password = module.params["password"]
    state = module.params["state"]
    user_name = module.params["name"]
    change_name = module.params["change_name"]
    description = module.params["description"]
    role = module.params["role"]
    user_password = module.params["user_password"]
    inactivity_timeout = module.params["inactivity_timeout"]
    full_name = module.params["full_name"]
    email_addr = module.params["email_addr"]
    disabled = module.params["disabled"]
    auth_password = module.params["auth_password"]
    unlock = module.params["unlock"]

    if (username is None or password is None or hostname is None):
        module.fail_json(
            msg="Missing variables: hostname, username and password is mandatory.")

    # defaults
    return_status = changed = False
    msg = "No task to run."
    resp = None
    try:
        client_obj = client.NimOSClient(
            hostname,
            username,
            password,
            f"HPE Nimble Ansible Modules v{NIMBLE_ANSIBLE_VERSION}"
        )

        # States
        if ((unlock is None or unlock is False) and (state == "create" or state == "present")):
            if not client_obj.users.get(id=None, name=user_name) or state == "create":
                return_status, changed, msg, changed_attrs_dict, resp = create_user(
                    client_obj,
                    user_name,
                    user_password,
                    description=description,
                    role=role,
                    inactivity_timeout=inactivity_timeout,
                    full_name=full_name,
                    email_addr=email_addr,
                    disabled=disabled)
            else:
                # update op
                return_status, changed, msg, changed_attrs_dict, resp = update_user(
                    client_obj,
                    user_name,
                    name=change_name,
                    password=user_password,
                    description=description,
                    role=role,
                    inactivity_timeout=inactivity_timeout,
                    full_name=full_name,
                    email_addr=email_addr,
                    disabled=disabled,
                    auth_password=auth_password)

        elif state == "absent":
            return_status, changed, msg, changed_attrs_dict = delete_user(client_obj, user_name)

        elif state == "present" and unlock is True:
            return_status, changed, msg, changed_attrs_dict = unlock_user(client_obj, user_name)

    except Exception as ex:
        # failed for some reason.
        msg = str(ex)

    if return_status:
        if utils.is_null_or_empty(resp):
            module.exit_json(return_status=return_status, changed=changed, msg=msg)
        else:
            module.exit_json(return_status=return_status, changed=changed, msg=msg, attrs=resp)
    else:
        module.fail_json(return_status=return_status, changed=changed, msg=msg)


if __name__ == '__main__':
    main()

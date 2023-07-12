#!/usr/bin/python

# Copyright 2020 Hewlett Packard Enterprise Development LP
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
description: Manage the user policies on an HPE Nimble Storage group.
module: hpe_nimble_user_policy
options:
  allowed_attempts:
    required: False
    type: int
    description:
    - Number of authentication attempts allowed before the user account is locked. Allowed range is [1, 10] inclusive. '0' indicates no limit.
  digit:
    required: False
    type: int
    description:
    - Number of numerical characters required in user passwords. Allowed range is [0, 255] inclusive.
  lower:
    required: False
    type: int
    description:
    - Number of lowercase characters required in user passwords. Allowed range is [0, 255] inclusive.
  max_sessions:
    required: False
    type: int
    description:
    - Maximum number of sessions allowed for a group. Allowed range is [10, 1000] inclusive.
  min_length:
    required: False
    type: int
    description:
    - Minimum length for user passwords. Allowed range is [8, 255] inclusive.
  no_reuse:
    required: False
    type: int
    description:
    - Number of times that a password must change before you can reuse a previous password. Allowed range is [1,20] inclusive.
  previous_diff:
    required: False
    type: int
    description:
    - Number of characters that must be different from the previous password. Allowed range is [1, 255] inclusive.
  special:
    required: False
    type: int
    description:
    - Number of special characters required in user passwords. Allowed range is [0, 255] inclusive.
  state:
    required: True
    choices:
      - present
    type: str
    description:
    - The user policy operation.
  upper:
    required: False
    type: int
    description:
    - Number of uppercase characters required in user passwords. Allowed range is [0, 255] inclusive.
extends_documentation_fragment: hpe.nimble.hpe_nimble
short_description: Manage the HPE Nimble Storage user policies
version_added: "1.0.0"
notes:
  - This module does not support C(check_mode).
'''

EXAMPLES = r'''

- name: Update user policy
  hpe.nimble.hpe_nimble_user_policy:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    upper: "{{ upper }}"
    allowed_attempts: 2
    min_length: 10
    state: "present"

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


def update_user_policy(
        client_obj,
        **kwargs):

    try:
        user_resp = client_obj.user_policies.get()
        if utils.is_null_or_empty(user_resp):
            return (False, False, "User policy is not present on Array", {}, {})

        changed_attrs_dict, params = utils.remove_unchanged_or_null_args(user_resp, **kwargs)
        if changed_attrs_dict.__len__() > 0:
            user_resp = client_obj.user_policies.update(id=user_resp.attrs.get("id"), **params)
            return (True, True, f"Updated user policy successfully with following attributes '{changed_attrs_dict}'.", changed_attrs_dict, user_resp.attrs)
        else:
            return (True, False, "User Policy already present in given state.", {}, user_resp.attrs)
    except Exception as ex:
        return (False, False, f"User Policy Update failed | {ex}", {}, {})


def main():

    fields = {
        "state": {
            "required": True,
            "choices": ['present'
                        ],
            "type": 'str'
        },
        "allowed_attempts": {
            "required": False,
            "type": "int"
        },
        "min_length": {
            "required": False,
            "type": "int"
        },
        "upper": {
            "required": False,
            "type": "int"
        },
        "lower": {
            "required": False,
            "type": "int"
        },
        "digit": {
            "required": False,
            "type": "int"
        },
        "special": {
            "required": False,
            "type": "int"
        },
        "previous_diff": {
            "required": False,
            "type": "int"
        },
        "no_reuse": {
            "required": False,
            "type": "int"
        },
        "max_sessions": {
            "required": False,
            "type": "int"
        }
    }
    default_fields = utils.basic_auth_arg_fields()
    fields.update(default_fields)
    module = AnsibleModule(argument_spec=fields)
    if client is None:
        module.fail_json(msg='the python nimble_sdk module is required')

    hostname = module.params["host"]
    username = module.params["username"]
    password = module.params["password"]
    state = module.params["state"]
    allowed_attempts = module.params["allowed_attempts"]
    min_length = module.params["min_length"]
    upper = module.params["upper"]
    lower = module.params["lower"]
    digit = module.params["digit"]
    special = module.params["special"]
    previous_diff = module.params["previous_diff"]
    no_reuse = module.params["no_reuse"]
    max_sessions = module.params["max_sessions"]

    if (username is None or password is None or hostname is None):
        module.fail_json(
            msg="Storage system IP or username or password is null")
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
        if state == "present":
            return_status, changed, msg, changed_attrs_dict, resp = update_user_policy(
                client_obj,
                allowed_attempts=allowed_attempts,
                min_length=min_length,
                upper=upper,
                lower=lower,
                digit=digit,
                special=special,
                previous_diff=previous_diff,
                no_reuse=no_reuse,
                max_sessions=max_sessions)

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

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
description: Manage the encryption on an Nimble Storage group.
module: hpe_nimble_encryption
options:
  active:
    type: bool
    description:
    - Whether the master key is active or not.
  age:
    required: False
    type: int
    description:
    - Minimum age (in hours) of inactive encryption keys to be purged. '0' indicates to purge the keys immediately.
  encryption_config:
    required: False
    type: dict
    description:
    - How encryption is configured for this group. Group encryption settings.
  group_encrypt:
    required: False
    type: bool
    description:
    - Flag for setting group encryption.
  name:
    required: True
    type: str
    description:
    - Name of the master key. The only allowed value is "default".
  passphrase:
    required: False
    type: str
    description:
    - Passphrase used to protect the master key, required during creation, enabling/disabling the key and change the
      passphrase to a new value. String with size from 8 to 64 printable characters.
  purge_inactive:
    required: False
    type: bool
    description:
    - Purges encryption keys that have been inactive for the age or longer. If you do not specify an age, the keys will be purged immediately.
  new_passphrase:
    required: False
    type: str
    description:
    - When changing the passphrase, this attribute specifies the new value of the passphrase. String with size from 8 to 64 printable characters.
  state:
    required: True
    choices:
    -  create
    -  present
    -  absent
    type: str
    description:
    - The encryption operation.
extends_documentation_fragment: hpe.nimble.hpe_nimble
short_description: Manage the HPE Nimble Storage encryption
version_added: "1.0.0"
notes:
  - This module does not support C(check_mode).
'''

EXAMPLES = r'''

# if state is create, then create master key, fails if it exist or cannot create
# if state is present, then create master key if not present ,else success
- name: Create master key
  hpe.nimble.hpe_nimble_encryption:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "default"
    passphrase: "{{ passphrase }}"
    active: "{{ active | default('false') }}"
    state: "{{ state | default('present') }}"

- name: Delete master key
  hpe.nimble.hpe_nimble_encryption:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "default"
    state: "absent"

- name: Purge inactive master key
  hpe.nimble.hpe_nimble_encryption:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "default"
    age: "{{ age | mandatory }}"
    state: "present"
    purge_inactive: true

- name: Group encryption
  hpe.nimble.hpe_nimble_encryption:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "{{ name }}"
    encryption_config: "{{ encryption_config | mandatory }}"
    state: "present"
    group_encrypt: true

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


def create_master_key(
        client_obj,
        master_key,
        passphrase):

    if utils.is_null_or_empty(master_key):
        return (False, False, "Create master key failed as no key is provided.", {}, {})

    try:
        master_key_resp = client_obj.master_key.get(id=None, name=master_key)
        if utils.is_null_or_empty(master_key_resp):
            master_key_resp = client_obj.master_key.create(name=master_key, passphrase=passphrase)
            return (True, True, f"Master key '{master_key}' created successfully.", {}, master_key_resp.attrs)
        else:
            return (False, False, f"Master key '{master_key}' cannot be created as it is already present in given state.", {}, master_key_resp.attrs)
    except Exception as ex:
        return (False, False, f"Master key creation failed |{ex}", {}, {})


def update_master_key(
        client_obj,
        master_key,
        **kwargs):

    if utils.is_null_or_empty(master_key):
        return (False, False, "Update master key failed as master key is not present.", {}, {})

    try:
        master_key_resp = client_obj.master_key.get(id=None, name=master_key)
        if utils.is_null_or_empty(master_key_resp):
            return (False, False, f"Master key '{master_key}' cannot be updated as it is not present.", {}, {})

        changed_attrs_dict, params = utils.remove_unchanged_or_null_args(master_key_resp, **kwargs)
        changed_attrs_dict.pop('passphrase')
        if changed_attrs_dict.__len__() > 0:
            master_key_resp = client_obj.master_key.update(id=master_key_resp.attrs.get("id"), name=master_key, **params)
            return (True, True, f"Master key '{master_key}' already present. Modified the following attributes '{changed_attrs_dict}'",
                    changed_attrs_dict, master_key_resp.attrs)
        else:
            return (True, False, f"Master key '{master_key}' already present in given state.", {}, master_key_resp.attrs)
    except Exception as ex:
        return (False, False, f"Master key update failed |{ex}", {}, {})


def delete_master_key(
        client_obj,
        master_key):

    if utils.is_null_or_empty(master_key):
        return (False, False, "Delete master key failed as master key is not present.", {})

    try:
        master_key_resp = client_obj.master_key.get(id=None, name=master_key)
        if utils.is_null_or_empty(master_key_resp):
            return (False, False, f"Master key '{master_key}' cannot be deleted as it is not present.", {})

        client_obj.master_key.delete(id=master_key_resp.attrs.get("id"))
        return (True, True, f"Deleted master key '{master_key}' successfully.", {})
    except Exception as ex:
        return (False, False, f"Delete master key failed |{ex}", {})


def purge_inactive_key(
        client_obj,
        master_key,
        **kwargs):

    if utils.is_null_or_empty(master_key):
        return (False, False, "Purge inactive master key failed as master key is not present.", {})

    try:
        master_key_resp = client_obj.master_key.get(id=None, name=master_key)
        if utils.is_null_or_empty(master_key_resp):
            return (False, False, f"Master key '{master_key}' cannot be purged as it is not present.", {})

        params = utils.remove_null_args(**kwargs)
        client_obj.master_key.purge_inactive(id=master_key_resp.attrs.get("id"), **params)
        return (True, True, f"Purged inactive master key '{master_key}' successfully.", {})
    except Exception as ex:
        return (False, False, f"Purge inactive master key failed |{ex}", {})


def group_encryption(
        client_obj,
        group_name,
        encryption_config):

    if utils.is_null_or_empty(group_name):
        return (False, False, "Encryption setting for group failed as group name is not present.", {}, {})

    try:
        group_resp = client_obj.groups.get(id=None, name=group_name)
        if utils.is_null_or_empty(group_resp):
            return (False, False, f"Encryption setting for group '{group_name}' cannot be done as it is not present.", {}, {})
        changed_attrs_dict, params = utils.remove_unchanged_or_null_args(group_resp, encryption_config=encryption_config)
        if changed_attrs_dict.__len__() > 0:
            group_resp = client_obj.groups.update(id=group_resp.attrs.get("id"), encryption_config=encryption_config)
            return (True, True, f"Encryption setting for group '{group_name}' changed successfully. ", changed_attrs_dict, group_resp.attrs)
        else:
            return (True, False, f"Encryption setting for group '{group_resp.attrs.get('name')}' is already in same state.", {}, group_resp.attrs)
    except Exception as ex:
        return (False, False, f"Encryption setting for group failed |{ex}", {}, {})


def main():

    fields = {
        "active": {
            "required": False,
            "type": "bool"
        },
        "age": {
            "required": False,
            "type": "int"
        },
        "encryption_config": {
            "required": False,
            "type": "dict"
        },
        "group_encrypt": {
            "required": False,
            "type": "bool"
        },
        "name": {
            "required": True,
            "type": "str"
        },
        "passphrase": {
            "required": False,
            "type": "str",
            "no_log": True
        },
        "purge_inactive": {
            "required": False,
            "type": "bool"
        },
        "new_passphrase": {
            "required": False,
            "type": "str",
            "no_log": True
        },
        "state": {
            "required": True,
            "choices": ['create',
                        'present',
                        'absent'
                        ],
            "type": "str"
        }
    }
    default_fields = utils.basic_auth_arg_fields()
    fields.update(default_fields)
    required_if = [('state', 'create', ['passphrase'])]

    module = AnsibleModule(argument_spec=fields, required_if=required_if)
    if client is None:
        module.fail_json(msg='Python nimble-sdk could not be found.')

    hostname = module.params["host"]
    username = module.params["username"]
    password = module.params["password"]
    active = module.params["active"]
    age = module.params["age"]
    encryption_config = module.params["encryption_config"]
    group_encrypt = module.params["group_encrypt"]
    master_key = module.params["name"]
    passphrase = module.params["passphrase"]
    purge_inactive = module.params["purge_inactive"]
    new_passphrase = module.params["new_passphrase"]
    state = module.params["state"]

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
        if ((purge_inactive is None or purge_inactive is False)
            and (group_encrypt is None or group_encrypt is False)
                and (state == "create" or state == "present")):
            if not client_obj.master_key.get(id=None, name=master_key) or state == "create":
                return_status, changed, msg, changed_attrs_dict, resp = create_master_key(
                    client_obj,
                    master_key,
                    passphrase)
            else:
                # update op
                return_status, changed, msg, changed_attrs_dict, resp = update_master_key(
                    client_obj,
                    master_key,
                    active=active,
                    passphrase=passphrase,
                    new_passphrase=new_passphrase)

        elif state == "absent":
            return_status, changed, msg, changed_attrs_dict = delete_master_key(client_obj, master_key)

        elif state == "present" and purge_inactive is True:
            return_status, changed, msg, changed_attrs_dict = purge_inactive_key(
                client_obj,
                master_key,
                age=age)

        elif state == "present" and group_encrypt is True:
            group_name = module.params["name"]
            return_status, changed, msg, changed_attrs_dict, resp = group_encryption(
                client_obj,
                group_name,
                encryption_config)
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

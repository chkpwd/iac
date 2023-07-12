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
description: Manage the storage pools on an HPE Nimble Storage group.
module: hpe_nimble_pool
options:
  array_list:
    required: False
    type: list
    elements: dict
    description:
    - List of arrays in the pool with detailed information. To create or update array list, only array ID is required.
  change_name:
    required: False
    type: str
    description:
    - Change name of the existing pool.
  description:
    required: False
    type: str
    description:
    - Text description of pool.
  dedupe_all_volumes:
    type: bool
    description:
    - Indicates if dedupe is enabled by default for new volumes on this pool.
  force:
    required: False
    type:  bool
    description:
    - Forcibly delete the specified pool even if it contains deleted volumes whose space is being reclaimed.
      Forcibly remove an array from array_list via an update operation even if the array is not reachable.
      There should no volumes in the pool for the force update operation to succeed.
  is_default:
    required: False
    type: bool
    description:
    - Indicates if this is the default pool.
  merge:
    required: False
    type: bool
    description:
    - Merge the specified pool into the target pool. All volumes on the specified pool are moved to the target pool and the
      specified pool is then deleted. All the arrays in the pool are assigned to the target pool.
  name:
    required: True
    type: str
    description:
    - Name of the pool.
  state:
    required: True
    choices:
    - present
    - absent
    - create
    type: str
    description:
    - The pool operation.
  target:
    required: False
    type: str
    description:
    - Name of the target pool.
extends_documentation_fragment: hpe.nimble.hpe_nimble
short_description: Manage the HPE Nimble Storage pools
version_added: "1.0.0"
notes:
  - This module does not support C(check_mode).
'''

EXAMPLES = r'''

# if state is create , then create a pool if not present. Fails if already present.
# if state is present, then create a pool if not present. Succeed if it already exists.
- name: Create pool if not present
  hpe.nimble.hpe_nimble_pool:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    state: "{{ state | default('present') }}"
    name: "{{ name }}"
    array_list: "{{ array_list }} "
    description: "{{ description }}"

- name: Delete pool
  hpe.nimble.hpe_nimble_pool:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "{{ name }}"
    state: absent

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


def create_pool(
        client_obj,
        pool_name,
        **kwargs):

    if utils.is_null_or_empty(pool_name):
        return (False, False, "Create pool failed as pool name is not present.", {}, {})

    try:
        pool_resp = client_obj.pools.get(id=None, name=pool_name)
        if utils.is_null_or_empty(pool_resp):
            params = utils.remove_null_args(**kwargs)
            pool_resp = client_obj.pools.create(name=pool_name,
                                                **params)
            if pool_resp is not None:
                return (True, True, f"Created pool '{pool_name}' successfully.", {}, pool_resp.attrs)
        else:
            return (False, False, f"Pool '{pool_name}' cannot be created as it is already present in given state.", {}, pool_resp.attrs)
    except Exception as ex:
        return (False, False, f"Pool creation failed | {ex}", {}, {})


def update_pool(
        client_obj,
        pool_resp,
        **kwargs):

    if utils.is_null_or_empty(pool_resp):
        return (False, False, "Update pool failed as pool name is not present.", {}, {})
    try:
        pool_name = pool_resp.attrs.get("name")
        changed_attrs_dict, params = utils.remove_unchanged_or_null_args(pool_resp, **kwargs)
        if changed_attrs_dict.__len__() > 0:
            pool_resp = client_obj.pools.update(id=pool_resp.attrs.get("id"), **params)
            return (True, True, f"Pool '{pool_name}' already present. Modified the following attributes '{changed_attrs_dict}'",
                    changed_attrs_dict, pool_resp.attrs)
        else:
            return (True, False, f"Pool '{pool_name}' already present in given state.", {}, pool_resp.attrs)

    except Exception as ex:
        return (False, False, f"Pool update failed | {ex}", {}, {})


def delete_pool(
        client_obj,
        pool_name):

    if utils.is_null_or_empty(pool_name):
        return (False, False, "Delete pool failed as pool name is not present.", {})

    try:
        pool_resp = client_obj.pools.get(id=None, name=pool_name)
        if utils.is_null_or_empty(pool_resp):
            return (False, False, f"Cannot delete pool '{pool_name}' as it is not present.", {})
        else:
            pool_resp = client_obj.pools.delete(id=pool_resp.attrs.get("id"))
            return (True, True, f"Deleted pool '{pool_name}' successfully.", {})
    except Exception as ex:
        return (False, False, f"Pool deletion failed | {ex}", {})


def merge_pool(
        client_obj,
        pool_name,
        target,
        **kwargs):

    if utils.is_null_or_empty(pool_name):
        return (False, False, "Merge pool failed as pool name is not present.", {}, {})
    if utils.is_null_or_empty(target):
        return (False, False, "Delete pool failed as target pool name is not present.", {}, {})

    try:
        pool_resp = client_obj.pools.get(id=None, name=pool_name)
        if utils.is_null_or_empty(pool_resp):
            return (False, False, f"Merge pools failed as source pool '{pool_name}' is not present.", {}, {})
        target_pool_resp = client_obj.pools.get(id=None, name=target)
        if utils.is_null_or_empty(target_pool_resp):
            return (False, False, f"Merge pools failed as target pool '{target}' is not present.", {}, {})

        params = utils.remove_null_args(**kwargs)
        resp = client_obj.pools.merge(id=pool_resp.attrs.get("id"),
                                      target_pool_id=target_pool_resp.attrs.get("id"),
                                      **params)
        if hasattr(resp, 'attrs'):
            resp = resp.attrs
        return (True, True, f"Merged target pool '{target}' to pool '{pool_name}' successfully.", {}, resp)
    except Exception as ex:
        return (False, False, f"Merge pool failed | {ex}", {}, {})


def main():

    fields = {
        "array_list": {
            "required": False,
            "type": "list",
            "elements": 'dict'
        },
        "change_name": {
            "required": False,
            "type": "str"
        },
        "description": {
            "required": False,
            "type": "str"
        },
        "dedupe_all_volumes": {
            "required": False,
            "type": "bool"
        },
        "force": {
            "required": False,
            "type": "bool"
        },
        "is_default": {
            "required": False,
            "type": "bool"
        },
        "merge": {
            "required": False,
            "type": "bool"
        },
        "name": {
            "required": True,
            "type": "str"
        },
        "state": {
            "required": True,
            "choices": ['present',
                        'absent',
                        'create'
                        ],
            "type": "str"
        },
        "target": {
            "required": False,
            "type": "str"
        }
    }
    default_fields = utils.basic_auth_arg_fields()
    fields.update(default_fields)
    required_if = [('state', 'create', ['array_list'])]

    module = AnsibleModule(argument_spec=fields, required_if=required_if)
    if client is None:
        module.fail_json(msg='Python nimble-sdk could not be found.')

    hostname = module.params["host"]
    username = module.params["username"]
    password = module.params["password"]
    state = module.params["state"]
    pool_name = module.params["name"]
    change_name = module.params["change_name"]
    description = module.params["description"]
    array_list = module.params["array_list"]
    force = module.params["force"]
    dedupe_all_volumes = module.params["dedupe_all_volumes"]
    is_default = module.params["is_default"]
    target = module.params["target"]
    merge = module.params["merge"]

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
        if state == 'present' and merge is True:
            return_status, changed, msg, changed_attrs_dict, resp = merge_pool(
                client_obj,
                pool_name,
                target,
                force=force)

        elif (merge is None or merge is False) and (state == "create" or state == "present"):
            pool_resp = client_obj.pools.get(id=None, name=pool_name)

            if utils.is_null_or_empty(pool_resp) or state == "create":
                return_status, changed, msg, changed_attrs_dict, resp = create_pool(
                    client_obj,
                    pool_name,
                    description=description,
                    array_list=array_list,
                    dedupe_all_volumes=dedupe_all_volumes)
            else:
                # update op
                return_status, changed, msg, changed_attrs_dict, resp = update_pool(
                    client_obj,
                    pool_resp,
                    name=change_name,
                    description=description,
                    array_list=array_list,
                    force=force,
                    dedupe_all_volumes=dedupe_all_volumes,
                    is_default=is_default)

        elif state == "absent":
            return_status, changed, msg, changed_attrs_dict = delete_pool(
                client_obj,
                pool_name)
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

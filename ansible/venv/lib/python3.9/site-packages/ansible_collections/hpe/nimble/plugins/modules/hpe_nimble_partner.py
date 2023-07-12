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
description: Manage the replication partner on an HPE Nimble Storage group.
module: hpe_nimble_partner
options:
  control_port:
    required: False
    type: int
    description:
    - Port number of partner control interface. Value -1 for an invalid port or a positive integer value up to 65535 representing the TCP/IP port.
  data_port:
    required: False
    type: int
    description:
    - Port number of partner data interface. Value -1 for an invalid port or a positive integer value up to 65535 representing the TCP/IP port.
  description:
    required: False
    type: str
    description:
    - Description of replication partner.
  downstream_hostname:
    required: True
    type: str
    description:
    - IP address or hostname of partner interface. This must be the partner's Group Management IP address.
      String of up to 64 alphanumeric characters, - and . and ':' are allowed after first character.
  folder:
    required: False
    type: str
    description:
    - The Folder ID within the pool where volumes replicated from this partner will be created. This is not supported for pool partners.
  match_folder:
    required: False
    type: bool
    description:
    - Indicates whether to match the upstream volume's folder on the downstream.
  name:
    required: False
    type: str
    description:
    - Name of replication partner. String of up to 64 alphanumeric characters, - and . and  ':' are allowed after first character.
  pause:
    required: False
    type: bool
    description:
    - Pause replication for the specified partner.
  pool:
    required: False
    type: str
    description:
    - The pool name where volumes replicated from this partner will be created. Replica volumes created as clones ignore
      this parameter and are always created in the same pool as their parent volume.
  repl_data_hostname:
    required: False
    type: str
    description:
    - IP address or hostname of partner data interface. String of up to 64 alphanumeric characters, - and . and ':' are allowed after first character.
  resume:
    required: False
    type: bool
    description:
    - Resume replication for the specified partner.
  secret:
    required: False
    type: str
    description:
    - Replication partner shared secret, used for mutual authentication of the partners.
  state:
    required: True
    choices:
    -  create
    -  present
    -  absent
    type: str
    description:
    - The replication partner operation.
  subnet_label:
    required: False
    type: str
    description:
    - Indicates whether to match the upstream volume's folder on the downstream.
  subnet_type:
    required: False
    choices:
    - invalid
    - unconfigured
    - unconfigured
    - mgmt
    - data
    - mgmt_data
    type: str
    description:
    - Type of the subnet used to replicate to this partner.
  test:
    required: False
    type: bool
    description:
    - Test connectivity to the specified partner.
  throttles:
    required: False
    type: list
    elements: dict
    description:
    - Throttles used while replicating from/to this partner. All the throttles for the partner.
extends_documentation_fragment: hpe.nimble.hpe_nimble
short_description: Manage the HPE Nimble Storage Replication Partner
version_added: "1.0.0"
notes:
  - This module does not support C(check_mode).
'''

EXAMPLES = r'''

# if state is create, then create partner, fails if it exist or cannot create
# if state is present, then create partner if not present ,else success
- name: Create Partner
  hpe.nimble.hpe_nimble_partner:
    host: "{{ host }}"  # upstream host
    username: "{{ username }}"
    password: "{{ password }}"
    name: "{{ name | mandatory }}"
    description: "{{ description }}"
    downstream_hostname: "{{ downstream_hostname | mandatory }}"
    secret: "{{ secret | mandatory }}"
    subnet_label: "{{ subnet_label | mandatory }}"
    state: "{{ state | default('present') }}"

- name: Delete Partner
  hpe.nimble.hpe_nimble_partner:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    downstream_hostname: "{{ downstream_hostname | mandatory }}"
    state: "absent"

- name: Test Partner
  hpe.nimble.hpe_nimble_partner:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    downstream_hostname: "{{ downstream_hostname | mandatory }}"
    state: "present"
    test: true

- name: Pause Partner
  hpe.nimble.hpe_nimble_partner:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    downstream_hostname: "{{ downstream_hostname | mandatory }}"
    state: "present"
    pause: true

- name: Resume Partner
  hpe.nimble.hpe_nimble_partner:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    downstream_hostname: "{{ downstream_hostname | mandatory }}"
    state: "present"
    resume: true

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


def create_partner(
        client_obj,
        downstream_hostname,  # downstream
        **kwargs):

    if utils.is_null_or_empty(downstream_hostname):
        return (False, False, "Create replication partner failed as name is not present.", {})

    try:
        upstream_repl_resp = client_obj.replication_partners.get(id=None, hostname=downstream_hostname)
        if utils.is_null_or_empty(upstream_repl_resp):
            params = utils.remove_null_args(**kwargs)
            upstream_repl_resp = client_obj.replication_partners.create(hostname=downstream_hostname, **params)
            return (True, True, f"Replication partner '{downstream_hostname}' created successfully.", {}, upstream_repl_resp.attrs)
        else:
            return (False, False, f"Replication partner '{downstream_hostname}' cannot be created as it is already present in given state.",
                    {}, upstream_repl_resp.attrs)
    except Exception as ex:
        return (False, False, f"Replication partner creation failed |{ex}", {}, {})


def update_partner(
        client_obj,
        downstream_hostname,  # downstream
        secret,
        **kwargs):

    if utils.is_null_or_empty(downstream_hostname):
        return (False, False, "Update replication partner failed as no downstream partner is provided.", {}, {})

    try:
        upstream_repl_resp = client_obj.replication_partners.get(id=None, hostname=downstream_hostname)
        if utils.is_null_or_empty(upstream_repl_resp):
            return (False, False, f"Replication partner '{downstream_hostname}' cannot be updated as it is not present.", {}, {})

        changed_attrs_dict, params = utils.remove_unchanged_or_null_args(upstream_repl_resp, **kwargs)
        if changed_attrs_dict.__len__() > 0:
            upstream_repl_resp = client_obj.replication_partners.update(id=upstream_repl_resp.attrs.get("id"), secret=secret, **params)
            return (True, True, f"Replication partner '{downstream_hostname}' already present. Modified the following attributes '{changed_attrs_dict}'",
                    changed_attrs_dict, upstream_repl_resp.attrs)
        else:
            return (True, False, f"Replication partner '{upstream_repl_resp.attrs.get('name')}' already present in given state.", {}, upstream_repl_resp.attrs)
    except Exception as ex:
        return (False, False, f"Replication partner update failed |{ex}", {}, {})


def delete_partner(
        client_obj,
        downstream_hostname):

    if utils.is_null_or_empty(downstream_hostname):
        return (False, False, "Delete replication partner failed as no downstream partner is provided.", {})

    try:
        upstream_repl_resp = client_obj.replication_partners.get(id=None, hostname=downstream_hostname)
        if utils.is_null_or_empty(upstream_repl_resp):
            return (False, False, f"Replication partner '{downstream_hostname}' cannot be deleted as it is not present.", {})
        client_obj.replication_partners.delete(id=upstream_repl_resp.attrs.get("id"))

        return (True, True, f"Deleted replication partner '{downstream_hostname}' successfully.", {})
    except Exception as ex:
        return (False, False, f"Delete replication partner failed |{ex}", {})


def test_partner(
        client_obj,
        downstream_hostname):

    if utils.is_null_or_empty(downstream_hostname):
        return (False, False, "Test replication partner failed as no downstream partner is provided.", {})

    try:
        upstream_repl_resp = client_obj.replication_partners.get(id=None, hostname=downstream_hostname)
        if utils.is_null_or_empty(upstream_repl_resp):
            return (False, False, f"Replication partner '{downstream_hostname}' cannot be tested as it is not present.", {})

        client_obj.replication_partners.test(id=upstream_repl_resp.attrs.get("id"))
        return (True, False, f"Tested replication partner '{downstream_hostname}' successfully.", {})
    except Exception as ex:
        return (False, False, f"Test replication partner failed |{ex}", {})


def pause_partner(
        client_obj,
        downstream_hostname):

    if utils.is_null_or_empty(downstream_hostname):
        return (False, False, "Pause replication partner failed as no downstream partner is provided.", {})

    try:
        upstream_repl_resp = client_obj.replication_partners.get(id=None, hostname=downstream_hostname)
        if utils.is_null_or_empty(upstream_repl_resp):
            return (False, False, f"Replication partner '{downstream_hostname}' cannot be paused as it is not present.", {})
        if upstream_repl_resp.attrs.get("paused") is False:
            client_obj.replication_partners.pause(id=upstream_repl_resp.attrs.get("id"))
            return (True, True, f"Paused replication partner '{downstream_hostname}' successfully.", {})
        else:
            return (True, False, f"Replication partner '{downstream_hostname}' is already in paused state.", {})
    except Exception as ex:
        return (False, False, f"Pause replication partner failed |{ex}", {})


def resume_partner(
        client_obj,
        downstream_hostname):

    if utils.is_null_or_empty(downstream_hostname):
        return (False, False, "Resume replication partner failed as no downstream partner is provided.", {})

    try:
        upstream_repl_resp = client_obj.replication_partners.get(id=None, hostname=downstream_hostname)
        if utils.is_null_or_empty(upstream_repl_resp):
            return (False, False, f"Replication partner '{downstream_hostname}' cannot be resumed as it is not present.", {})

        client_obj.replication_partners.resume(id=upstream_repl_resp.attrs.get("id"))
        return (True, True, f"Resumed replication partner '{downstream_hostname}' successfully.", {})
    except Exception as ex:
        return (False, False, f"Resume replication partner failed |{ex}", {})


def main():

    fields = {
        "control_port": {
            "required": False,
            "type": "int"
        },
        "data_port": {
            "required": False,
            "type": "int"
        },
        "description": {
            "required": False,
            "type": "str"
        },
        "folder": {
            "required": False,
            "type": "str"
        },
        "match_folder": {
            "required": False,
            "type": "bool"
        },
        "name": {
            "required": False,
            "type": "str"
        },
        "downstream_hostname": {
            "required": True,
            "type": "str"
        },
        "pause": {
            "required": False,
            "type": "bool"
        },
        "pool": {
            "required": False,
            "type": "str"
        },
        "repl_data_hostname": {
            "required": False,
            "type": "str"
        },
        "resume": {
            "required": False,
            "type": "bool"
        },
        "secret": {
            "required": False,
            "type": "str",
            "no_log": True
        },
        "subnet_label": {
            "required": False,
            "type": "str"
        },
        "subnet_type": {
            "required": False,
            "choices": ['invalid',
                        'unconfigured',
                        'unconfigured',
                        'mgmt',
                        'data',
                        'mgmt_data'
                        ],
            "type": "str"
        },
        "test": {
            "required": False,
            "type": "bool"
        },
        "throttles": {
            "required": False,
            "type": "list",
            "elements": 'dict'
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
    required_if = [('state', 'create', ['subnet_label', 'secret', 'downstream_hostname', 'name'])]

    module = AnsibleModule(argument_spec=fields, required_if=required_if)
    if client is None:
        module.fail_json(msg='Python nimble-sdk could not be found.')

    hostname = module.params["host"]
    username = module.params["username"]
    password = module.params["password"]
    control_port = module.params["control_port"]
    data_port = module.params["data_port"]
    description = module.params["description"]
    folder = module.params["folder"]
    match_folder = module.params["match_folder"]
    repl_partner_name = module.params["name"]
    downstream_hostname = module.params["downstream_hostname"]
    pause = module.params["pause"]
    pool = module.params["pool"]
    repl_data_hostname = module.params["repl_data_hostname"]
    resume = module.params["resume"]
    secret = module.params["secret"]
    subnet_label = module.params["subnet_label"]
    subnet_type = module.params["subnet_type"]
    test = module.params["test"]
    throttles = module.params["throttles"]
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
        if ((test is None or test is False)
            and (resume is None or resume is False)
            and (pause is None or pause is False)
                and (state == "create" or state == "present")):
            if not client_obj.replication_partners.get(id=None, hostname=downstream_hostname) or state == "create":
                return_status, changed, msg, changed_attrs_dict, resp = create_partner(
                    client_obj,
                    downstream_hostname,
                    control_port=control_port,
                    data_port=data_port,
                    description=description,
                    folder_id=utils.get_folder_id(client_obj, folder),
                    match_folder=match_folder,
                    name=repl_partner_name,  # downstream partner name
                    pool_id=utils.get_pool_id(client_obj, pool),
                    repl_hostname=repl_data_hostname,
                    secret=secret,
                    subnet_label=subnet_label,
                    subnet_type=subnet_type,
                    throttles=throttles)
            else:
                # update op
                return_status, changed, msg, changed_attrs_dict, resp = update_partner(
                    client_obj,
                    downstream_hostname,
                    secret,
                    control_port=control_port,
                    data_port=data_port,
                    description=description,
                    folder_id=utils.get_folder_id(client_obj, folder),
                    match_folder=match_folder,
                    name=repl_partner_name,  # downstream partner name
                    pool_id=utils.get_pool_id(client_obj, pool),
                    repl_hostname=repl_data_hostname,
                    subnet_label=subnet_label,
                    subnet_type=subnet_type,
                    throttles=throttles)

        elif state == "absent":
            return_status, changed, msg, changed_attrs_dict = delete_partner(client_obj, downstream_hostname)

        elif state == "present" and test is True:
            return_status, changed, msg, changed_attrs_dict = test_partner(client_obj, downstream_hostname)

        elif state == "present" and pause is True:
            return_status, changed, msg, changed_attrs_dict = pause_partner(client_obj, downstream_hostname)

        elif state == "present" and resume is True:
            return_status, changed, msg, changed_attrs_dict = resume_partner(client_obj, downstream_hostname)
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

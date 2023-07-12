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
description: Manage the protection templates on an HPE Nimble Storage group.
module: hpe_nimble_protection_template
options:
  agent_hostname:
    required: False
    type: str
    description:
    - Generic backup agent hostname.
  agent_password:
    required: False
    type: str
    description:
    - Generic backup agent password.
  agent_username:
    required: False
    type: str
    description:
    - Generic backup agent username.
  app_cluster:
    required: False
    type: str
    description:
    - If the application is running within a windows cluster environment, this is the cluster name.
  app_id:
    required: False
    choices:
        - inval
        - exchange
        - exchange_dag
        - hyperv
        - sql2005
        - sql2008
        - sql2012
        - sql2014
        - sql2016
        - sql2017
    type: str
    description:
    - Application ID running on the server.
  app_server:
    required: False
    type: str
    description:
    - Application server hostname.
  app_service_name:
    required: False
    type: str
    description:
    - If the application is running within a windows cluster environment then this is the instance name of the service running within the cluster environment.
  app_sync:
    choices:
        - none
        - vss
        - vmware
        - generic
    required: False
    type: str
    description:
    - Application synchronization.
  change_name:
    required: False
    type: str
    description:
    - Change name of the existing protection template.
  description:
    required: False
    type: str
    description:
    - Text description of protection template.
  name:
    required: True
    type: str
    description:
    - Name of the protection template.
  state:
    required: True
    choices:
        - present
        - absent
        - create
    type: str
    description:
    - The protection template operations.
  vcenter_hostname:
    required: False
    type: str
    description:
    - VMware vCenter hostname.
  vcenter_password:
    required: False
    type: str
    description:
    - Application VMware vCenter password. A password with few constraints.
  vcenter_username:
    required: False
    type: str
    description:
    - Application VMware vCenter username. String of up to 80 alphanumeric characters, beginning with a letter.
      It can include ampersand (@), backslash (\), dash (-), period (.), and underscore (_).
extends_documentation_fragment: hpe.nimble.hpe_nimble
short_description: Manage the HPE Nimble Storage protection templates
version_added: "1.0.0"
notes:
  - This module does not support C(check_mode).
'''

EXAMPLES = r'''

# if state is create , then create a protection template if not present. Fails if already present.
# if state is present, then create a protection template if not present. Succeed if it already exists.
- name: Create protection template if not present
  hpe.nimble.hpe_nimble_protection_template:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "{{ name }}"
    description: "{{ description | default(None)}}"
    state: "{{ state | default('present') }}"

- name: Delete protection template
  hpe.nimble.hpe_nimble_protection_template:
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


def create_prot_template(
        client_obj,
        prot_template_name,
        **kwargs):

    if utils.is_null_or_empty(prot_template_name):
        return (False, False, "Create protection template failed as protection template name is not present.", {}, {})
    try:
        prot_template_resp = client_obj.protection_templates.get(id=None, name=prot_template_name)
        if utils.is_null_or_empty(prot_template_resp):
            params = utils.remove_null_args(**kwargs)
            prot_template_resp = client_obj.protection_templates.create(name=prot_template_name, **params)
            return (True, True, f"Protection template '{prot_template_name}' created successfully.", {}, prot_template_resp.attrs)
        else:
            return (False, False, f"Protection template '{prot_template_name}' cannot be created as it is already present in given state.",
                    {}, prot_template_resp.attrs)
    except Exception as ex:
        return (False, False, f"Protection template creation failed | {ex}", {}, {})


def update_prot_template(
        client_obj,
        prot_template_resp,
        **kwargs):

    if utils.is_null_or_empty(prot_template_resp):
        return (False, False, "Update protection template failed as protection template is not present.", {}, {})
    try:
        prot_template_name = prot_template_resp.attrs.get("name")
        changed_attrs_dict, params = utils.remove_unchanged_or_null_args(prot_template_resp, **kwargs)
        if changed_attrs_dict.__len__() > 0:
            prot_template_resp = client_obj.protection_templates.update(id=prot_template_resp.attrs.get("id"), **params)
            return (True, True, f"Protection template '{prot_template_name}' already present. Modified the following attributes '{changed_attrs_dict}'",
                    changed_attrs_dict, prot_template_resp.attrs)
        else:
            return (True, False, f"Protection template '{prot_template_name}' already present in given state.", {}, prot_template_resp.attrs)
    except Exception as ex:
        return (False, False, f"Protection template update failed | {ex}", {}, {})


def delete_prot_template(client_obj, prot_template_name):

    if utils.is_null_or_empty(prot_template_name):
        return (False, False, "Protection template deletion failed as protection template name is not present.", {})

    try:
        prot_template_resp = client_obj.protection_templates.get(id=None, name=prot_template_name)
        if utils.is_null_or_empty(prot_template_resp):
            return (False, False, f"Protection template '{prot_template_name}' not present to delete.", {})
        else:
            client_obj.protection_templates.delete(id=prot_template_resp.attrs.get("id"))
            return (True, True, f"Deleted protection template '{prot_template_name}' successfully.", {})
    except Exception as ex:
        return (False, False, f"Protection template deletion failed | {ex}", {})


def main():

    fields = {
        "state": {
            "required": True,
            "choices": ['present',
                        'absent',
                        'create'
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
        "app_sync": {
            "choices": ['none', 'vss', 'vmware', 'generic'],
            "required": False,
            "type": "str"
        },
        "app_server": {
            "required": False,
            "type": "str"
        },
        "app_id": {
            "required": False,
            "choices": ['inval', 'exchange', 'exchange_dag', 'hyperv', 'sql2005', 'sql2008', 'sql2012', 'sql2014', 'sql2016', 'sql2017'],
            "type": "str"
        },
        "app_cluster": {
            "required": False,
            "type": "str"
        },
        "app_service_name": {
            "required": False,
            "type": "str"
        },
        "vcenter_hostname": {
            "required": False,
            "type": "str"
        },
        "vcenter_username": {
            "required": False,
            "type": "str"
        },
        "vcenter_password": {
            "required": False,
            "type": "str",
            "no_log": True
        },
        "agent_hostname": {
            "required": False,
            "type": "str"
        },
        "agent_username": {
            "required": False,
            "type": "str"
        },
        "agent_password": {
            "required": False,
            "type": "str",
            "no_log": True
        }
    }
    default_fields = utils.basic_auth_arg_fields()
    fields.update(default_fields)
    module = AnsibleModule(argument_spec=fields)
    if client is None:
        module.fail_json(msg='Python nimble-sdk could not be found.')

    hostname = module.params["host"]
    username = module.params["username"]
    password = module.params["password"]
    state = module.params["state"]
    prot_template_name = module.params["name"]
    change_name = module.params["change_name"]
    description = module.params["description"]
    app_sync = module.params["app_sync"]
    app_server = module.params["app_server"]
    app_id = module.params["app_id"]
    app_cluster = module.params["app_cluster"]
    app_service_name = module.params["app_service_name"]
    vcenter_hostname = module.params["vcenter_hostname"]
    vcenter_username = module.params["vcenter_username"]
    vcenter_password = module.params["vcenter_password"]
    agent_hostname = module.params["agent_hostname"]
    agent_username = module.params["agent_username"]
    agent_password = module.params["agent_password"]

    if (username is None or password is None or hostname is None or prot_template_name is None):
        module.fail_json(
            msg="Missing variables: hostname, username, password and protection template is mandatory.")

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
        if state == "create" or state == "present":
            prot_template_resp = client_obj.protection_templates.get(id=None, name=prot_template_name)
            if utils.is_null_or_empty(prot_template_resp) or state == "create":
                return_status, changed, msg, changed_attrs_dict, resp = create_prot_template(
                    client_obj,
                    prot_template_name,
                    description=description,
                    app_sync=app_sync,
                    app_server=app_server,
                    app_id=app_id,
                    app_cluster_name=app_cluster,
                    app_service_name=app_service_name,
                    vcenter_hostname=vcenter_hostname,
                    vcenter_username=vcenter_username,
                    vcenter_password=vcenter_password,
                    agent_hostname=agent_hostname,
                    agent_username=agent_username,
                    agent_password=agent_password)
            else:
                # update op
                return_status, changed, msg, changed_attrs_dict, resp = update_prot_template(
                    client_obj,
                    prot_template_resp,
                    name=change_name,
                    description=description,
                    app_sync=app_sync,
                    app_server=app_server,
                    app_id=app_id, app_cluster_name=app_cluster,
                    app_service_name=app_service_name,
                    vcenter_hostname=vcenter_hostname,
                    vcenter_username=vcenter_username,
                    vcenter_password=vcenter_password,
                    agent_hostname=agent_hostname,
                    agent_username=agent_username,
                    agent_password=agent_password)

        elif state == "absent":
            return_status, changed, msg, changed_attrs_dict = delete_prot_template(client_obj, prot_template_name)
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

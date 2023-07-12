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
  - Alok Ranjan (@ranjanal)
description: Manage the protection schedules on an HPE Nimble Storage group.
module: hpe_nimble_protection_schedule
options:
  at_time:
    required: False
    type: int
    default: 0
    description:
    - Time of day when snapshot should be taken. In case repeat frequency specifies more than one snapshot
      in a day then the until_time option specifies until what time of day to take snapshots.
  change_name:
    required: False
    type: str
    description:
    - Change the name of existing protection schedule.
  days:
    required: False
    type: str
    description:
    - Specifies which days snapshots should be taken. Comma separated list of days of the week or 'all'.
  description:
    required: False
    type: str
    description:
    - Description of the schedule.
  disable_appsync:
    required: False
    type: bool
    description:
    - Disables application synchronized snapshots and creates crash consistent snapshots instead.
  downstream_partner:
    required: False
    type: str
    description:
    - Specifies the partner name if snapshots created by this schedule should be replicated.
  name:
    required: True
    type: str
    description:
    - Name of the protection schedule to create.
  num_retain:
    required: False
    type: int
    description:
    - Number of snapshots to retain. If replication is enabled on this schedule the array will always retain the latest
      replicated snapshot, which may exceed the specified retention value. This is necessary to ensure efficient replication performance.
  num_retain_replica:
    required: False
    type: int
    default: 0
    description:
    - Number of snapshots to retain on the replica.
  period:
    required: False
    type: int
    description:
    - Repeat interval for snapshots with respect to the period_unit. For example,
      a value of 2 with the 'period_unit' of 'hours' results in one snapshot every 2 hours.
  period_unit:
    choices:
      - minutes
      - hours
      - days
      - weeks
    required: False
    type: str
    description:
    - Time unit over which to take the number of snapshots specified in 'period'. For example, a value of 'days' with a
      'period' of '1' results in one snapshot every day.
  prot_template_name:
    required: False
    type: str
    description:
    - Name of the protection template in which this protection schedule is attached to.
  repl_alert_thres:
    required: False
    type: int
    description:
    - Replication alert threshold in seconds. If the replication of a snapshot takes more than this amount of time to complete
      an alert will be generated. Enter 0 to disable this alert.
  replicate_every:
    required: False
    type: int
    description:
    - Specifies which snapshots should be replicated. If snapshots are replicated and this option is not specified, every snapshot is replicated.
  schedule_type:
    choices:
      - regular
      - external_trigger
    required: False
    type: str
    description:
    - Normal schedules have internal timers which drive snapshot creation. An externally driven schedule has no internal timers.
      All snapshot activity is driven by an external trigger. In other words, these schedules are used only for externally driven manual snapshots.
  skip_db_consistency_check:
    required: False
    type: bool
    description:
    - Skip consistency check for database files on snapshots created by this schedule. This option only applies to snapshot schedules of a protection
      template with application synchronization set to VSS, application ID set to MS Exchange 2010 or later w/DAG, this schedule's snap_verify option
      set to yes, and its disable_appsync option set to false. Skipping consistency checks is only recommended if each database in a DAG has multiple copies.
  snap_verify:
    required: False
    type: bool
    description:
    - Run verification tool on snapshot created by this schedule. This option can only be used with snapshot schedules of a protection template
      that has application synchronization. The tool used to verify snapshot depends on the type of application. For example, if application
      synchronization is VSS and the application ID is Exchange, eseutil tool is run on the snapshots. If verification fails, the logs are not truncated.
  state:
    required: True
    choices:
      - present
      - absent
      - create
    type: str
    description:
    - The protection schedule operations
  until_time:
    required: False
    type: int
    description:
    - Time of day to stop taking snapshots. Applicable only when repeat frequency specifies more than one snapshot in a day.
  use_downstream_for_DR:
    required: False
    type: bool
    description:
    - Break synchronous replication for the specified volume collection and present downstream volumes to host(s). Downstream volumes in the volume
      collection will be set to online and presented to the host(s) using new serial and LUN numbers. No changes will be made to the upstream volumes,
      their serial and LUN numbers, and their online state. The existing ACLs on the upstream volumes will be copied to the downstream volumes.
      Use this in conjunction with an empty downstream_partner_id. This unconfigures synchronous replication when the partner is removed from the
      last replicating schedule in the specified volume collection and presents the downstream volumes to host(s). Host(s) will need to be configured
      to access the new volumes with the newly assigned serial and LUN numbers. Use this option to expose downstream volumes in a synchronously replicated
      volume collection to host(s) only when the upstream partner is confirmed to be down and there is no communication between partners. Do not execute this
      operation if a previous Group Management Service takeover has been performed on a different array. Do not perform a subsequent Group Management Service
      takeover on a different array as it will lead to irreconcilable conflicts. This limitation is cleared once the Group management service backup array has
      successfully synchronized after reconnection.
  volcoll_or_prottmpl_type:
    choices:
      - protection_template
      - volume_collection
    required: True
    type: str
    description:
    - Type of the protection policy this schedule is attached to.
  volcoll_name:
    required: False
    type: str
    description:
    - Name of the volume collection in which this protection schedule is attached to.
extends_documentation_fragment: hpe.nimble.hpe_nimble
short_description: Manage the HPE Nimble Storage protection schedules
version_added: "1.0.0"
notes:
  - This module does not support C(check_mode).
'''

EXAMPLES = r'''

# if state is create , then create a protection schedule if not present. Fails if already present.
# if state is present, then create a protection schedule if not present. Succeed if it already exists.
- name: Create protection schedule if not present
  hpe.nimble.hpe_nimble_protection_schedule:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "{{ name }}"
    description: "{{ description | default(None)}}"
    state: "{{ state | default('present') }}"
    volcoll_or_prottmpl_type: "{{ volcoll_or_prottmpl_type }}"
    prot_template_name: "{{ prot_template_name }}"
    num_retain: "{{ num_retain }}"

- name: Delete protection schedule
  hpe.nimble.hpe_nimble_protection_schedule:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "{{ name }}"
    volcoll_or_prottmpl_type: "{{ volcoll_or_prottmpl_type }}"
    volcoll_name: "{{ volcoll_name }}"
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


def create_prot_schedule(
        client_obj,
        prot_schedule_name,
        **kwargs):

    if utils.is_null_or_empty(prot_schedule_name):
        return (False, False, "Create protection schedule failed as protection schedule name is not present.", {}, {})
    try:
        prot_schedule_resp = client_obj.protection_schedules.get(id=None,
                                                                 name=prot_schedule_name,
                                                                 volcoll_or_prottmpl_type=kwargs['volcoll_or_prottmpl_type'],
                                                                 volcoll_or_prottmpl_id=kwargs['volcoll_or_prottmpl_id'])
        if utils.is_null_or_empty(prot_schedule_resp):
            params = utils.remove_null_args(**kwargs)
            prot_schedule_resp = client_obj.protection_schedules.create(name=prot_schedule_name, **params)
            return (True, True, f"Created protection schedule '{prot_schedule_name}' successfully.", {}, prot_schedule_resp.attrs)
        else:
            return (False, False, f"Cannot create protection schedule '{prot_schedule_name}' as it is already present in given state.",
                    {}, prot_schedule_resp.attrs)
    except Exception as ex:
        return (False, False, f"Protection schedule creation failed | {ex}", {}, {})


def update_prot_schedule(
        client_obj,
        prot_schedule_resp,
        **kwargs):

    if utils.is_null_or_empty(prot_schedule_resp):
        return (False, False, "Update protection schedule failed as protection schedule is not present.", {}, {})
    try:
        prot_schedule_name = prot_schedule_resp.attrs.get("name")
        changed_attrs_dict, params = utils.remove_unchanged_or_null_args(prot_schedule_resp, **kwargs)
        if changed_attrs_dict.__len__() > 0:
            prot_schedule_resp = client_obj.protection_schedules.update(id=prot_schedule_resp.attrs.get("id"), **params)
            return (True, True, f"Protection schedule '{prot_schedule_name}' already present. Modified the following attributes '{changed_attrs_dict}'",
                    changed_attrs_dict, prot_schedule_resp.attrs)
        else:
            return (True, False, f"Protection schedule '{prot_schedule_name}' already present in given state.", {}, prot_schedule_resp.attrs)
    except Exception as ex:
        return (False, False, f"Protection schedule update failed |{ex}", {}, {})


def delete_prot_schedule(client_obj,
                         prot_schedule_name,
                         volcoll_or_prottmpl_type,
                         volcoll_or_prottmpl_id):

    if utils.is_null_or_empty(prot_schedule_name):
        return (False, False, "Protection schedule deletion failed as protection schedule name is not present", {})

    try:
        prot_schedule_resp = client_obj.protection_schedules.get(id=None,
                                                                 name=prot_schedule_name,
                                                                 volcoll_or_prottmpl_type=volcoll_or_prottmpl_type,
                                                                 volcoll_or_prottmpl_id=volcoll_or_prottmpl_id)
        if utils.is_null_or_empty(prot_schedule_resp):
            return (False, False, f"Protection schedule '{prot_schedule_name}' not present to delete.", {})
        else:
            client_obj.protection_schedules.delete(id=prot_schedule_resp.attrs.get("id"))
            return (True, True, f"Deleted protection schedule '{prot_schedule_name}' successfully.", {})
    except Exception as ex:
        return (False, False, f"Protection schedule deletion failed | {ex}", {})


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
        "volcoll_or_prottmpl_type": {
            "choices": ['protection_template', 'volume_collection'],
            "required": True,
            "type": "str"
        },
        "volcoll_name": {
            "required": False,
            "type": "str"
        },
        "prot_template_name": {
            "required": False,
            "type": "str"
        },
        "period": {
            "required": False,
            "type": "int"
        },
        "period_unit": {
            "choices": ['minutes', 'hours', 'days', 'weeks'],
            "required": False,
            "type": "str"
        },
        "at_time": {
            "required": False,
            "type": "int"
        },
        "until_time": {
            "required": False,
            "type": "int"
        },
        "days": {
            "required": False,
            "type": "str"
        },
        "num_retain": {
            "required": False,
            "type": "int"
        },
        "downstream_partner": {
            "required": False,
            "type": "str"
        },
        "replicate_every": {
            "required": False,
            "type": "int"
        },
        "num_retain_replica": {
            "required": False,
            "type": "int"
        },
        "repl_alert_thres": {
            "required": False,
            "type": "int"
        },
        "snap_verify": {
            "required": False,
            "type": "bool"
        },
        "skip_db_consistency_check": {
            "required": False,
            "type": "bool"
        },
        "disable_appsync": {
            "required": False,
            "type": "bool"
        },
        "schedule_type": {
            "choices": ['regular', 'external_trigger'],
            "required": False,
            "type": "str"
        },
        "use_downstream_for_DR": {
            "required": False,
            "type": "bool"
        }
    }

    mutually_exclusive = [
        ['prot_template_name', 'volcoll_name']
    ]
    required_if = [
        ['state', 'create', ['num_retain']]
    ]
    required_one_of = [
        ['volcoll_name', 'prot_template_name']
    ]
    default_fields = utils.basic_auth_arg_fields()
    fields.update(default_fields)
    module = AnsibleModule(argument_spec=fields, mutually_exclusive=mutually_exclusive, required_if=required_if, required_one_of=required_one_of)
    if client is None:
        module.fail_json(msg='Python nimble-sdk could not be found.')

    hostname = module.params["host"]
    username = module.params["username"]
    password = module.params["password"]
    state = module.params["state"]
    prot_schedule_name = module.params["name"]
    change_name = module.params["change_name"]
    description = module.params["description"]
    volcoll_or_prottmpl_type = module.params["volcoll_or_prottmpl_type"]
    volcoll_name = module.params["volcoll_name"]
    prot_template_name = module.params["prot_template_name"]
    period = module.params["period"]
    period_unit = module.params["period_unit"]
    at_time = module.params["at_time"]
    until_time = module.params["until_time"]
    days = module.params["days"]
    num_retain = module.params["num_retain"]
    downstream_partner = module.params["downstream_partner"]
    replicate_every = module.params["replicate_every"]
    num_retain_replica = module.params["num_retain_replica"]
    repl_alert_thres = module.params["repl_alert_thres"]
    snap_verify = module.params["snap_verify"]
    skip_db_consistency_check = module.params["skip_db_consistency_check"]
    disable_appsync = module.params["disable_appsync"]
    schedule_type = module.params["schedule_type"]
    use_downstream_for_DR = module.params["use_downstream_for_DR"]

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
        if state == "create" or state == "present":
            # we need to enforce the below params as mandatory as there can be a scenario where in a protection schedule with the same name
            # exists in a different volume collection or in different protection tempalate. Hence, if a user wants to modify/update
            # a protection schedule , they need to provide all the three params for us to query and find the exact protection schedule
            if volcoll_name is None and prot_template_name is None or volcoll_or_prottmpl_type is None:
                module.fail_json(msg='Please provide the Mandatory params : volcoll_or_prottmpl_type, and volcoll_name or prot_template_name.')

            prot_schedule_resp = client_obj.protection_schedules.get(
                id=None,
                name=prot_schedule_name,
                volcoll_or_prottmpl_type=volcoll_or_prottmpl_type,
                volcoll_or_prottmpl_id=utils.get_volcoll_or_prottmpl_id(client_obj, volcoll_name, prot_template_name))

            if utils.is_null_or_empty(prot_schedule_resp) or state == "create":
                return_status, changed, msg, changed_attrs_dict, resp = create_prot_schedule(
                    client_obj,
                    prot_schedule_name,
                    description=description,
                    volcoll_or_prottmpl_type=volcoll_or_prottmpl_type,
                    volcoll_or_prottmpl_id=utils.get_volcoll_or_prottmpl_id(client_obj, volcoll_name, prot_template_name),
                    period=period,
                    period_unit=period_unit,
                    at_time=at_time,
                    until_time=until_time,
                    days=days,
                    num_retain=num_retain,
                    downstream_partner=downstream_partner,
                    downstream_partner_id=utils.get_downstream_partner_id(client_obj, downstream_partner),
                    replicate_every=replicate_every,
                    num_retain_replica=num_retain_replica,
                    repl_alert_thres=repl_alert_thres,
                    snap_verify=snap_verify,
                    skip_db_consistency_check=skip_db_consistency_check,
                    disable_appsync=disable_appsync,
                    schedule_type=schedule_type)
            else:
                # update op
                return_status, changed, msg, changed_attrs_dict, resp = update_prot_schedule(
                    client_obj,
                    prot_schedule_resp,
                    name=change_name,
                    description=description,
                    period=period,
                    period_unit=period_unit,
                    at_time=at_time,
                    until_time=until_time,
                    days=days,
                    num_retain=num_retain,
                    downstream_partner=downstream_partner,
                    downstream_partner_id=utils.get_downstream_partner_id(client_obj, downstream_partner),
                    replicate_every=replicate_every,
                    num_retain_replica=num_retain_replica,
                    repl_alert_thres=repl_alert_thres,
                    snap_verify=snap_verify,
                    skip_db_consistency_check=skip_db_consistency_check,
                    disable_appsync=disable_appsync,
                    schedule_type=schedule_type,
                    use_downstream_for_DR=use_downstream_for_DR)

        elif state == "absent":
            return_status, changed, msg, changed_attrs_dict = delete_prot_schedule(
                client_obj,
                prot_schedule_name,
                volcoll_or_prottmpl_type,
                utils.get_volcoll_or_prottmpl_id(client_obj, volcoll_name, prot_template_name))
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

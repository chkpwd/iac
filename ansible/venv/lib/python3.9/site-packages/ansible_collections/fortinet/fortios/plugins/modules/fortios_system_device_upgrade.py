#!/usr/bin/python
from __future__ import absolute_import, division, print_function

# Copyright: (c) 2022 Fortinet
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

__metaclass__ = type

ANSIBLE_METADATA = {
    "status": ["preview"],
    "supported_by": "community",
    "metadata_version": "1.1",
}

DOCUMENTATION = """
---
module: fortios_system_device_upgrade
short_description: Independent upgrades for managed devices in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and device_upgrade category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.0
version_added: "2.0.0"
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Hongbin Lu (@fgtdev-hblu)
    - Frank Shen (@frankshen01)
    - Miguel Angel Munoz (@mamunozgonzalez)
    - Nicolas Thomas (@thomnico)
notes:
    - Legacy fortiosapi has been deprecated, httpapi is the preferred way to run playbooks

requirements:
    - ansible>=2.9
options:
    access_token:
        description:
            - Token-based authentication.
              Generated from GUI of Fortigate.
        type: str
        required: false
    enable_log:
        description:
            - Enable/Disable logging for task.
        type: bool
        required: false
        default: false
    vdom:
        description:
            - Virtual domain, among those defined previously. A vdom is a
              virtual instance of the FortiGate that can be configured and
              used as a different unit.
        type: str
        default: root
    member_path:
        type: str
        description:
            - Member attribute path to operate on.
            - Delimited by a slash character if there are more than one attribute.
            - Parameter marked with member_path is legitimate for doing member operation.
    member_state:
        type: str
        description:
            - Add or delete a member under specified attribute path.
            - When member_state is specified, the state option is ignored.
        choices:
            - 'present'
            - 'absent'

    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        required: true
        choices:
            - 'present'
            - 'absent'
    system_device_upgrade:
        description:
            - Independent upgrades for managed devices.
        default: null
        type: dict
        suboptions:
            device_type:
                description:
                    - Fortinet device type.
                type: str
                choices:
                    - 'fortiswitch'
                    - 'fortiap'
                    - 'fortiextender'
            failure_reason:
                description:
                    - Upgrade failure reason.
                type: str
                choices:
                    - 'none'
                    - 'internal'
                    - 'timeout'
                    - 'device-type-unsupported'
                    - 'download-failed'
                    - 'device-missing'
                    - 'version-unavailable'
                    - 'staging-failed'
                    - 'reboot-failed'
                    - 'device-not-reconnected'
                    - 'node-not-ready'
                    - 'no-final-confirmation'
                    - 'no-confirmation-query'
                    - 'config-error-log-nonempty'
                    - 'node-failed'
            maximum_minutes:
                description:
                    - Maximum number of minutes to allow for immediate upgrade preparation.
                type: int
            serial:
                description:
                    - Serial number of the node to include.
                required: true
                type: str
            setup_time:
                description:
                    - 'Upgrade preparation start time in UTC (hh:mm yyyy/mm/dd UTC).'
                type: str
            status:
                description:
                    - Current status of the upgrade.
                type: str
                choices:
                    - 'disabled'
                    - 'initialized'
                    - 'downloading'
                    - 'device-disconnected'
                    - 'ready'
                    - 'coordinating'
                    - 'staging'
                    - 'final-check'
                    - 'upgrade-devices'
                    - 'cancelled'
                    - 'confirmed'
                    - 'done'
                    - 'failed'
            time:
                description:
                    - 'Scheduled upgrade execution time in UTC (hh:mm yyyy/mm/dd UTC).'
                type: str
            timing:
                description:
                    - Run immediately or at a scheduled time.
                type: str
                choices:
                    - 'immediate'
                    - 'scheduled'
            upgrade_path:
                description:
                    - Fortinet OS image versions to upgrade through in major-minor-patch format, such as 7-0-4.
                type: str
"""

EXAMPLES = """
- hosts: fortigates
  collections:
    - fortinet.fortios
  connection: httpapi
  vars:
   vdom: "root"
   ansible_httpapi_use_ssl: yes
   ansible_httpapi_validate_certs: no
   ansible_httpapi_port: 443
  tasks:
  - name: Independent upgrades for managed devices.
    fortios_system_device_upgrade:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      system_device_upgrade:
        device_type: "fortiswitch"
        failure_reason: "none"
        maximum_minutes: "15"
        serial: "<your_own_value>"
        setup_time: "<your_own_value>"
        status: "disabled"
        time: "<your_own_value>"
        timing: "immediate"
        upgrade_path: "<your_own_value>"

"""

RETURN = """
build:
  description: Build number of the fortigate image
  returned: always
  type: str
  sample: '1547'
http_method:
  description: Last method used to provision the content into FortiGate
  returned: always
  type: str
  sample: 'PUT'
http_status:
  description: Last result given by FortiGate on last operation applied
  returned: always
  type: str
  sample: "200"
mkey:
  description: Master key (id) used in the last call to FortiGate
  returned: success
  type: str
  sample: "id"
name:
  description: Name of the table used to fulfill the request
  returned: always
  type: str
  sample: "urlfilter"
path:
  description: Path of the table used to fulfill the request
  returned: always
  type: str
  sample: "webfilter"
revision:
  description: Internal revision number
  returned: always
  type: str
  sample: "17.0.2.10658"
serial:
  description: Serial number of the unit
  returned: always
  type: str
  sample: "FGVMEVYYQT3AB5352"
status:
  description: Indication of the operation's result
  returned: always
  type: str
  sample: "success"
vdom:
  description: Virtual domain used
  returned: always
  type: str
  sample: "root"
version:
  description: Version of the FortiGate
  returned: always
  type: str
  sample: "v5.6.3"

"""
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    FortiOSHandler,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    check_legacy_fortiosapi,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    schema_to_module_spec,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    check_schema_versioning,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortimanager.common import (
    FAIL_SOCKET_MSG,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.data_post_processor import (
    remove_invalid_fields,
)


def filter_system_device_upgrade_data(json):
    option_list = [
        "device_type",
        "failure_reason",
        "maximum_minutes",
        "serial",
        "setup_time",
        "status",
        "time",
        "timing",
        "upgrade_path",
    ]

    json = remove_invalid_fields(json)
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def underscore_to_hyphen(data):
    if isinstance(data, list):
        for i, elem in enumerate(data):
            data[i] = underscore_to_hyphen(elem)
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[k.replace("_", "-")] = underscore_to_hyphen(v)
        data = new_data

    return data


def system_device_upgrade(data, fos):
    vdom = data["vdom"]

    state = data["state"]

    system_device_upgrade_data = data["system_device_upgrade"]
    filtered_data = underscore_to_hyphen(
        filter_system_device_upgrade_data(system_device_upgrade_data)
    )

    if state == "present" or state is True:
        return fos.set("system", "device-upgrade", data=filtered_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "system", "device-upgrade", mkey=filtered_data["serial"], vdom=vdom
        )
    else:
        fos._module.fail_json(msg="state must be present or absent!")


def is_successful_status(resp):
    return (
        "status" in resp
        and resp["status"] == "success"
        or "http_status" in resp
        and resp["http_status"] == 200
        or "http_method" in resp
        and resp["http_method"] == "DELETE"
        and resp["http_status"] == 404
    )


def fortios_system(data, fos):

    fos.do_member_operation("system", "device-upgrade")
    if data["system_device_upgrade"]:
        resp = system_device_upgrade(data, fos)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_device_upgrade"))

    return (
        not is_successful_status(resp),
        is_successful_status(resp)
        and (resp["revision_changed"] if "revision_changed" in resp else True),
        resp,
        {},
    )


versioned_schema = {
    "type": "list",
    "elements": "dict",
    "children": {
        "serial": {
            "revisions": {"v7.4.0": True, "v7.2.4": True},
            "type": "string",
            "required": True,
        },
        "timing": {
            "revisions": {"v7.4.0": True, "v7.2.4": True},
            "type": "string",
            "options": [
                {"value": "immediate", "revisions": {"v7.4.0": True, "v7.2.4": True}},
                {"value": "scheduled", "revisions": {"v7.4.0": True, "v7.2.4": True}},
            ],
        },
        "maximum_minutes": {
            "revisions": {"v7.4.0": True, "v7.2.4": False},
            "type": "integer",
        },
        "time": {"revisions": {"v7.4.0": True, "v7.2.4": True}, "type": "string"},
        "setup_time": {"revisions": {"v7.4.0": True, "v7.2.4": True}, "type": "string"},
        "upgrade_path": {
            "revisions": {"v7.4.0": True, "v7.2.4": True},
            "type": "string",
        },
        "device_type": {
            "revisions": {"v7.4.0": True, "v7.2.4": True},
            "type": "string",
            "options": [
                {"value": "fortiswitch", "revisions": {"v7.4.0": True, "v7.2.4": True}},
                {"value": "fortiap", "revisions": {"v7.4.0": True, "v7.2.4": True}},
                {
                    "value": "fortiextender",
                    "revisions": {"v7.4.0": True, "v7.2.4": True},
                },
            ],
        },
        "status": {
            "revisions": {"v7.4.0": True, "v7.2.4": True},
            "type": "string",
            "options": [
                {"value": "disabled", "revisions": {"v7.4.0": True, "v7.2.4": True}},
                {"value": "initialized", "revisions": {"v7.4.0": True, "v7.2.4": True}},
                {"value": "downloading", "revisions": {"v7.4.0": True, "v7.2.4": True}},
                {
                    "value": "device-disconnected",
                    "revisions": {"v7.4.0": True, "v7.2.4": True},
                },
                {"value": "ready", "revisions": {"v7.4.0": True, "v7.2.4": True}},
                {
                    "value": "coordinating",
                    "revisions": {"v7.4.0": True, "v7.2.4": True},
                },
                {"value": "staging", "revisions": {"v7.4.0": True, "v7.2.4": True}},
                {"value": "final-check", "revisions": {"v7.4.0": True, "v7.2.4": True}},
                {
                    "value": "upgrade-devices",
                    "revisions": {"v7.4.0": True, "v7.2.4": True},
                },
                {"value": "cancelled", "revisions": {"v7.4.0": True, "v7.2.4": True}},
                {"value": "confirmed", "revisions": {"v7.4.0": True, "v7.2.4": True}},
                {"value": "done", "revisions": {"v7.4.0": True, "v7.2.4": True}},
                {"value": "failed", "revisions": {"v7.4.0": True, "v7.2.4": True}},
            ],
        },
        "failure_reason": {
            "revisions": {"v7.4.0": True, "v7.2.4": True},
            "type": "string",
            "options": [
                {"value": "none", "revisions": {"v7.4.0": True, "v7.2.4": True}},
                {"value": "internal", "revisions": {"v7.4.0": True, "v7.2.4": True}},
                {"value": "timeout", "revisions": {"v7.4.0": True, "v7.2.4": True}},
                {
                    "value": "device-type-unsupported",
                    "revisions": {"v7.4.0": True, "v7.2.4": True},
                },
                {
                    "value": "download-failed",
                    "revisions": {"v7.4.0": True, "v7.2.4": True},
                },
                {
                    "value": "device-missing",
                    "revisions": {"v7.4.0": True, "v7.2.4": True},
                },
                {
                    "value": "version-unavailable",
                    "revisions": {"v7.4.0": True, "v7.2.4": True},
                },
                {
                    "value": "staging-failed",
                    "revisions": {"v7.4.0": True, "v7.2.4": True},
                },
                {
                    "value": "reboot-failed",
                    "revisions": {"v7.4.0": True, "v7.2.4": True},
                },
                {
                    "value": "device-not-reconnected",
                    "revisions": {"v7.4.0": True, "v7.2.4": True},
                },
                {
                    "value": "node-not-ready",
                    "revisions": {"v7.4.0": True, "v7.2.4": True},
                },
                {
                    "value": "no-final-confirmation",
                    "revisions": {"v7.4.0": True, "v7.2.4": True},
                },
                {
                    "value": "no-confirmation-query",
                    "revisions": {"v7.4.0": True, "v7.2.4": True},
                },
                {
                    "value": "config-error-log-nonempty",
                    "revisions": {"v7.4.0": True, "v7.2.4": True},
                },
                {"value": "node-failed", "revisions": {"v7.4.0": True, "v7.2.4": True}},
            ],
        },
    },
    "revisions": {"v7.4.0": True, "v7.2.4": True},
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = "serial"
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "enable_log": {"required": False, "type": "bool", "default": False},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "member_path": {"required": False, "type": "str"},
        "member_state": {
            "type": "str",
            "required": False,
            "choices": ["present", "absent"],
        },
        "state": {"required": True, "type": "str", "choices": ["present", "absent"]},
        "system_device_upgrade": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_device_upgrade"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_device_upgrade"]["options"][attribute_name][
                "required"
            ] = True

    module = AnsibleModule(argument_spec=fields, supports_check_mode=False)
    check_legacy_fortiosapi(module)

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        if "access_token" in module.params:
            connection.set_option("access_token", module.params["access_token"])

        if "enable_log" in module.params:
            connection.set_option("enable_log", module.params["enable_log"])
        else:
            connection.set_option("enable_log", False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(
            fos, versioned_schema, "system_device_upgrade"
        )

        is_error, has_changed, result, diff = fortios_system(module.params, fos)

    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if versions_check_result and versions_check_result["matched"] is False:
        module.warn(
            "Ansible has detected version mismatch between FortOS system and your playbook, see more details by specifying option -vvv"
        )

    if not is_error:
        if versions_check_result and versions_check_result["matched"] is False:
            module.exit_json(
                changed=has_changed,
                version_check_warning=versions_check_result,
                meta=result,
                diff=diff,
            )
        else:
            module.exit_json(changed=has_changed, meta=result, diff=diff)
    else:
        if versions_check_result and versions_check_result["matched"] is False:
            module.fail_json(
                msg="Error in repo",
                version_check_warning=versions_check_result,
                meta=result,
            )
        else:
            module.fail_json(msg="Error in repo", meta=result)


if __name__ == "__main__":
    main()

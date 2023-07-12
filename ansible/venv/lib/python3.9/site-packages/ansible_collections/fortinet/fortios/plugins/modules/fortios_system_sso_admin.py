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
module: fortios_system_sso_admin
short_description: Configure SSO admin users in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and sso_admin category.
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
    system_sso_admin:
        description:
            - Configure SSO admin users.
        default: null
        type: dict
        suboptions:
            accprofile:
                description:
                    - SSO admin user access profile. Source system.accprofile.name.
                type: str
            gui_dashboard:
                description:
                    - GUI dashboards.
                type: list
                elements: dict
                suboptions:
                    columns:
                        description:
                            - Number of columns.
                        type: int
                    id:
                        description:
                            - Dashboard ID.
                        required: true
                        type: int
                    layout_type:
                        description:
                            - Layout type.
                        type: str
                        choices:
                            - 'responsive'
                            - 'fixed'
                    name:
                        description:
                            - Dashboard name.
                        type: str
                    permanent:
                        description:
                            - Permanent dashboard (can"t be removed via the GUI).
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    vdom:
                        description:
                            - Virtual domain. Source system.vdom.name.
                        type: str
                    widget:
                        description:
                            - Dashboard widgets.
                        type: list
                        elements: dict
                        suboptions:
                            fabric_device:
                                description:
                                    - Fabric device to monitor.
                                type: str
                            fabric_device_widget_name:
                                description:
                                    - Fabric device widget name.
                                type: str
                            fabric_device_widget_visualization_type:
                                description:
                                    - Visualization type for fabric device widget.
                                type: str
                            fortiview_device:
                                description:
                                    - FortiView device.
                                type: str
                            fortiview_filters:
                                description:
                                    - FortiView filters.
                                type: list
                                elements: dict
                                suboptions:
                                    id:
                                        description:
                                            - FortiView Filter ID.
                                        required: true
                                        type: int
                                    key:
                                        description:
                                            - Filter key.
                                        type: str
                                    value:
                                        description:
                                            - Filter value.
                                        type: str
                            fortiview_sort_by:
                                description:
                                    - FortiView sort by.
                                type: str
                            fortiview_timeframe:
                                description:
                                    - FortiView timeframe.
                                type: str
                            fortiview_type:
                                description:
                                    - FortiView type.
                                type: str
                            fortiview_visualization:
                                description:
                                    - FortiView visualization.
                                type: str
                            height:
                                description:
                                    - Height.
                                type: int
                            id:
                                description:
                                    - Widget ID.
                                required: true
                                type: int
                            industry:
                                description:
                                    - Security Audit Rating industry.
                                type: str
                                choices:
                                    - 'default'
                                    - 'custom'
                            interface:
                                description:
                                    - Interface to monitor. Source system.interface.name.
                                type: str
                            region:
                                description:
                                    - Security Audit Rating region.
                                type: str
                                choices:
                                    - 'default'
                                    - 'custom'
                            title:
                                description:
                                    - Widget title.
                                type: str
                            type:
                                description:
                                    - Widget type.
                                type: str
                                choices:
                                    - 'sysinfo'
                                    - 'licinfo'
                                    - 'forticloud'
                                    - 'cpu-usage'
                                    - 'memory-usage'
                                    - 'disk-usage'
                                    - 'log-rate'
                                    - 'sessions'
                                    - 'session-rate'
                                    - 'tr-history'
                                    - 'analytics'
                                    - 'usb-modem'
                                    - 'admins'
                                    - 'security-fabric'
                                    - 'security-fabric-ranking'
                                    - 'sensor-info'
                                    - 'ha-status'
                                    - 'vulnerability-summary'
                                    - 'host-scan-summary'
                                    - 'fortiview'
                                    - 'botnet-activity'
                                    - 'fabric-device'
                            width:
                                description:
                                    - Width.
                                type: int
                            x_pos:
                                description:
                                    - X position.
                                type: int
                            y_pos:
                                description:
                                    - Y position.
                                type: int
            gui_global_menu_favorites:
                description:
                    - Favorite GUI menu IDs for the global VDOM.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Select menu ID.
                        required: true
                        type: str
            gui_ignore_release_overview_version:
                description:
                    - The FortiOS version to ignore release overview prompt for.
                type: str
            gui_new_feature_acknowledge:
                description:
                    - Acknowledgement of new features.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Select menu ID.
                        required: true
                        type: str
            gui_vdom_menu_favorites:
                description:
                    - Favorite GUI menu IDs for VDOMs.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Select menu ID.
                        required: true
                        type: str
            name:
                description:
                    - SSO admin name.
                required: true
                type: str
            vdom:
                description:
                    - Virtual domain(s) that the administrator can access.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Virtual domain name. Source system.vdom.name.
                        required: true
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
  - name: Configure SSO admin users.
    fortios_system_sso_admin:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      system_sso_admin:
        accprofile: "<your_own_value> (source system.accprofile.name)"
        gui_dashboard:
         -
            columns: "10"
            id:  "6"
            layout_type: "responsive"
            name: "default_name_8"
            permanent: "disable"
            vdom: "<your_own_value> (source system.vdom.name)"
            widget:
             -
                fabric_device: "<your_own_value>"
                fabric_device_widget_name: "<your_own_value>"
                fabric_device_widget_visualization_type: "<your_own_value>"
                fortiview_device: "<your_own_value>"
                fortiview_filters:
                 -
                    id:  "17"
                    key: "<your_own_value>"
                    value: "<your_own_value>"
                fortiview_sort_by: "<your_own_value>"
                fortiview_timeframe: "<your_own_value>"
                fortiview_type: "<your_own_value>"
                fortiview_visualization: "<your_own_value>"
                height: "25"
                id:  "25"
                industry: "default"
                interface: "<your_own_value> (source system.interface.name)"
                region: "default"
                title: "<your_own_value>"
                type: "sysinfo"
                width: "25"
                x_pos: "500"
                y_pos: "500"
        gui_global_menu_favorites:
         -
            id:  "35"
        gui_ignore_release_overview_version: "<your_own_value>"
        gui_new_feature_acknowledge:
         -
            id:  "38"
        gui_vdom_menu_favorites:
         -
            id:  "40"
        name: "default_name_41"
        vdom:
         -
            name: "default_name_43 (source system.vdom.name)"

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
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    is_same_comparison,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    serialize,
)


def filter_system_sso_admin_data(json):
    option_list = [
        "accprofile",
        "gui_dashboard",
        "gui_global_menu_favorites",
        "gui_ignore_release_overview_version",
        "gui_new_feature_acknowledge",
        "gui_vdom_menu_favorites",
        "name",
        "vdom",
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


def system_sso_admin(data, fos, check_mode=False):

    vdom = data["vdom"]

    state = data["state"]

    system_sso_admin_data = data["system_sso_admin"]
    filtered_data = underscore_to_hyphen(
        filter_system_sso_admin_data(system_sso_admin_data)
    )

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("system", "sso-admin", filtered_data, vdom=vdom)
        current_data = fos.get("system", "sso-admin", vdom=vdom, mkey=mkey)
        is_existed = (
            current_data
            and current_data.get("http_status") == 200
            and isinstance(current_data.get("results"), list)
            and len(current_data["results"]) > 0
        )

        # 2. if it exists and the state is 'present' then compare current settings with desired
        if state == "present" or state is True:
            if mkey is None:
                return False, True, filtered_data, diff

            # if mkey exists then compare each other
            # record exits and they're matched or not
            if is_existed:
                is_same = is_same_comparison(
                    serialize(current_data["results"][0]), serialize(filtered_data)
                )
                return (
                    False,
                    not is_same,
                    filtered_data,
                    {"before": current_data["results"][0], "after": filtered_data},
                )

            # record does not exist
            return False, True, filtered_data, diff

        if state == "absent":
            if mkey is None:
                return (
                    False,
                    False,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )

            if is_existed:
                return (
                    False,
                    True,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )
            return False, False, filtered_data, {}

        return True, False, {"reason: ": "Must provide state parameter"}, {}

    if state == "present" or state is True:
        return fos.set("system", "sso-admin", data=filtered_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("system", "sso-admin", mkey=filtered_data["name"], vdom=vdom)
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


def fortios_system(data, fos, check_mode):

    fos.do_member_operation("system", "sso-admin")
    if data["system_sso_admin"]:
        resp = system_sso_admin(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_sso_admin"))
    if check_mode:
        return resp
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
        "name": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
            },
            "type": "string",
            "required": True,
        },
        "accprofile": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
            },
            "type": "string",
        },
        "vdom": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                    },
                    "type": "string",
                    "required": True,
                }
            },
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
            },
        },
        "gui_ignore_release_overview_version": {
            "revisions": {
                "v6.4.1": True,
                "v6.4.0": False,
                "v6.2.7": False,
                "v6.2.5": False,
                "v6.2.3": False,
                "v6.2.0": False,
            },
            "type": "string",
        },
        "gui_dashboard": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "revisions": {"v6.2.3": True},
                    "type": "integer",
                    "required": True,
                },
                "name": {"revisions": {"v6.2.3": True}, "type": "string"},
                "vdom": {"revisions": {"v6.2.3": True}, "type": "string"},
                "layout_type": {
                    "revisions": {"v6.2.3": True},
                    "type": "string",
                    "options": [
                        {"value": "responsive", "revisions": {"v6.2.3": True}},
                        {"value": "fixed", "revisions": {"v6.2.3": True}},
                    ],
                },
                "permanent": {
                    "revisions": {"v6.2.3": True},
                    "type": "string",
                    "options": [
                        {"value": "disable", "revisions": {"v6.2.3": True}},
                        {"value": "enable", "revisions": {"v6.2.3": True}},
                    ],
                },
                "columns": {"revisions": {"v6.2.3": True}, "type": "integer"},
                "widget": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "revisions": {"v6.2.3": True},
                            "type": "integer",
                            "required": True,
                        },
                        "type": {
                            "revisions": {"v6.2.3": True},
                            "type": "string",
                            "options": [
                                {"value": "sysinfo", "revisions": {"v6.2.3": True}},
                                {"value": "licinfo", "revisions": {"v6.2.3": True}},
                                {"value": "forticloud", "revisions": {"v6.2.3": True}},
                                {"value": "cpu-usage", "revisions": {"v6.2.3": True}},
                                {
                                    "value": "memory-usage",
                                    "revisions": {"v6.2.3": True},
                                },
                                {"value": "disk-usage", "revisions": {"v6.2.3": True}},
                                {"value": "log-rate", "revisions": {"v6.2.3": True}},
                                {"value": "sessions", "revisions": {"v6.2.3": True}},
                                {
                                    "value": "session-rate",
                                    "revisions": {"v6.2.3": True},
                                },
                                {"value": "tr-history", "revisions": {"v6.2.3": True}},
                                {"value": "analytics", "revisions": {"v6.2.3": True}},
                                {"value": "usb-modem", "revisions": {"v6.2.3": True}},
                                {"value": "admins", "revisions": {"v6.2.3": True}},
                                {
                                    "value": "security-fabric",
                                    "revisions": {"v6.2.3": True},
                                },
                                {
                                    "value": "security-fabric-ranking",
                                    "revisions": {"v6.2.3": True},
                                },
                                {"value": "sensor-info", "revisions": {"v6.2.3": True}},
                                {"value": "ha-status", "revisions": {"v6.2.3": True}},
                                {
                                    "value": "vulnerability-summary",
                                    "revisions": {"v6.2.3": True},
                                },
                                {
                                    "value": "host-scan-summary",
                                    "revisions": {"v6.2.3": True},
                                },
                                {"value": "fortiview", "revisions": {"v6.2.3": True}},
                                {
                                    "value": "botnet-activity",
                                    "revisions": {"v6.2.3": True},
                                },
                                {
                                    "value": "fabric-device",
                                    "revisions": {"v6.2.3": True},
                                },
                            ],
                        },
                        "x_pos": {"revisions": {"v6.2.3": True}, "type": "integer"},
                        "y_pos": {"revisions": {"v6.2.3": True}, "type": "integer"},
                        "width": {"revisions": {"v6.2.3": True}, "type": "integer"},
                        "height": {"revisions": {"v6.2.3": True}, "type": "integer"},
                        "interface": {"revisions": {"v6.2.3": True}, "type": "string"},
                        "region": {
                            "revisions": {"v6.2.3": True},
                            "type": "string",
                            "options": [
                                {"value": "default", "revisions": {"v6.2.3": True}},
                                {"value": "custom", "revisions": {"v6.2.3": True}},
                            ],
                        },
                        "industry": {
                            "revisions": {"v6.2.3": True},
                            "type": "string",
                            "options": [
                                {"value": "default", "revisions": {"v6.2.3": True}},
                                {"value": "custom", "revisions": {"v6.2.3": True}},
                            ],
                        },
                        "fabric_device": {
                            "revisions": {"v6.2.3": True},
                            "type": "string",
                        },
                        "fabric_device_widget_name": {
                            "revisions": {"v6.2.3": True},
                            "type": "string",
                        },
                        "fabric_device_widget_visualization_type": {
                            "revisions": {"v6.2.3": True},
                            "type": "string",
                        },
                        "title": {"revisions": {"v6.2.3": True}, "type": "string"},
                        "fortiview_type": {
                            "revisions": {"v6.2.3": True},
                            "type": "string",
                        },
                        "fortiview_sort_by": {
                            "revisions": {"v6.2.3": True},
                            "type": "string",
                        },
                        "fortiview_timeframe": {
                            "revisions": {"v6.2.3": True},
                            "type": "string",
                        },
                        "fortiview_visualization": {
                            "revisions": {"v6.2.3": True},
                            "type": "string",
                        },
                        "fortiview_device": {
                            "revisions": {"v6.2.3": True},
                            "type": "string",
                        },
                        "fortiview_filters": {
                            "type": "list",
                            "elements": "dict",
                            "children": {
                                "id": {
                                    "revisions": {"v6.2.3": True},
                                    "type": "integer",
                                    "required": True,
                                },
                                "key": {
                                    "revisions": {"v6.2.3": True},
                                    "type": "string",
                                },
                                "value": {
                                    "revisions": {"v6.2.3": True},
                                    "type": "string",
                                },
                            },
                            "revisions": {"v6.2.3": True},
                        },
                    },
                    "revisions": {"v6.2.3": True},
                },
            },
            "revisions": {"v6.2.3": True, "v6.2.0": False},
        },
        "gui_global_menu_favorites": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "revisions": {"v6.2.3": True},
                    "type": "string",
                    "required": True,
                }
            },
            "revisions": {"v6.2.3": True, "v6.2.0": False},
        },
        "gui_vdom_menu_favorites": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "revisions": {"v6.2.3": True},
                    "type": "string",
                    "required": True,
                }
            },
            "revisions": {"v6.2.3": True, "v6.2.0": False},
        },
        "gui_new_feature_acknowledge": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "revisions": {"v6.2.3": True},
                    "type": "string",
                    "required": True,
                }
            },
            "revisions": {"v6.2.3": True, "v6.2.0": False},
        },
    },
    "revisions": {
        "v7.4.0": True,
        "v7.2.4": True,
        "v7.2.2": True,
        "v7.2.1": True,
        "v7.2.0": True,
        "v7.0.8": True,
        "v7.0.7": True,
        "v7.0.6": True,
        "v7.0.5": True,
        "v7.0.4": True,
        "v7.0.3": True,
        "v7.0.2": True,
        "v7.0.1": True,
        "v7.0.0": True,
        "v6.4.4": True,
        "v6.4.1": True,
        "v6.4.0": True,
        "v6.2.7": True,
        "v6.2.5": True,
        "v6.2.3": True,
        "v6.2.0": True,
    },
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = "name"
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
        "system_sso_admin": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_sso_admin"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["system_sso_admin"]["options"][attribute_name]["required"] = True

    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)
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
            fos, versioned_schema, "system_sso_admin"
        )

        is_error, has_changed, result, diff = fortios_system(
            module.params, fos, module.check_mode
        )

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

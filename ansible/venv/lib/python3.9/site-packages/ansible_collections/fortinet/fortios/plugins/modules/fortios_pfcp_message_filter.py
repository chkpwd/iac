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
module: fortios_pfcp_message_filter
short_description: Message filter for PFCP messages in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify pfcp feature and message_filter category.
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
    pfcp_message_filter:
        description:
            - Message filter for PFCP messages.
        default: null
        type: dict
        suboptions:
            association_release:
                description:
                    - Allow or deny PFCP association release request (9) and PFCP association release response (10).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            association_setup:
                description:
                    - Allow or deny PFCP association setup request (5) and PFCP association setup response (6).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            association_update:
                description:
                    - Allow or deny PFCP association update request (7) and PFCP association update response (8).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            heartbeat:
                description:
                    - Allow or deny PFCP heartbeat request (1) and PFCP heartbeat response (2).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            name:
                description:
                    - Message filter name.
                required: true
                type: str
            node_report:
                description:
                    - Allow or deny PFCP node report request (12) and PFCP node report response (13).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            pfd_management:
                description:
                    - Allow or deny PFCP PFD management request (3) and PFCP PFD management response (4).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            session_deletion:
                description:
                    - Allow or deny PFCP session deletion request (54) and PFCP session deletion response (55).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            session_establish:
                description:
                    - Allow or deny PFCP session establishment request (50) and PFCP session establishment response (51).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            session_modification:
                description:
                    - Allow or deny PFCP session modification request (52) and PFCP session modification response (53).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            session_report:
                description:
                    - Allow or deny PFCP session report request (56) and PFCP session report response (57).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            session_set_deletion:
                description:
                    - Allow or deny PFCP session set deletion request (14) and PFCP session set deletion response (15).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            unknown_message:
                description:
                    - Allow or deny unknown messages.
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            unknown_message_allow_list:
                description:
                    - Allow list of unknown messages.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Message IDs (range from 1 to 255).
                        required: true
                        type: int
            version_not_support:
                description:
                    - Allow or deny PFCP version not supported response (11).
                type: str
                choices:
                    - 'allow'
                    - 'deny'
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
  - name: Message filter for PFCP messages.
    fortios_pfcp_message_filter:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      pfcp_message_filter:
        association_release: "allow"
        association_setup: "allow"
        association_update: "allow"
        heartbeat: "allow"
        name: "default_name_7"
        node_report: "allow"
        pfd_management: "allow"
        session_deletion: "allow"
        session_establish: "allow"
        session_modification: "allow"
        session_report: "allow"
        session_set_deletion: "allow"
        unknown_message: "allow"
        unknown_message_allow_list:
         -
            id:  "17"
        version_not_support: "allow"

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


def filter_pfcp_message_filter_data(json):
    option_list = [
        "association_release",
        "association_setup",
        "association_update",
        "heartbeat",
        "name",
        "node_report",
        "pfd_management",
        "session_deletion",
        "session_establish",
        "session_modification",
        "session_report",
        "session_set_deletion",
        "unknown_message",
        "unknown_message_allow_list",
        "version_not_support",
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


def pfcp_message_filter(data, fos):
    vdom = data["vdom"]

    state = data["state"]

    pfcp_message_filter_data = data["pfcp_message_filter"]
    filtered_data = underscore_to_hyphen(
        filter_pfcp_message_filter_data(pfcp_message_filter_data)
    )

    if state == "present" or state is True:
        return fos.set("pfcp", "message-filter", data=filtered_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "pfcp", "message-filter", mkey=filtered_data["name"], vdom=vdom
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


def fortios_pfcp(data, fos):

    fos.do_member_operation("pfcp", "message-filter")
    if data["pfcp_message_filter"]:
        resp = pfcp_message_filter(data, fos)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("pfcp_message_filter"))

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
                "v7.2.4": True,
                "v7.2.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
            },
            "type": "string",
            "required": True,
        },
        "unknown_message": {
            "revisions": {
                "v7.2.4": True,
                "v7.2.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
            },
            "type": "string",
            "options": [
                {
                    "value": "allow",
                    "revisions": {
                        "v7.2.4": True,
                        "v7.2.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                    },
                },
                {
                    "value": "deny",
                    "revisions": {
                        "v7.2.4": True,
                        "v7.2.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                    },
                },
            ],
        },
        "unknown_message_allow_list": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "revisions": {
                        "v7.2.4": True,
                        "v7.2.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                    },
                    "type": "integer",
                    "required": True,
                }
            },
            "revisions": {
                "v7.2.4": True,
                "v7.2.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
            },
        },
        "heartbeat": {
            "revisions": {
                "v7.2.4": True,
                "v7.2.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
            },
            "type": "string",
            "options": [
                {
                    "value": "allow",
                    "revisions": {
                        "v7.2.4": True,
                        "v7.2.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                    },
                },
                {
                    "value": "deny",
                    "revisions": {
                        "v7.2.4": True,
                        "v7.2.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                    },
                },
            ],
        },
        "pfd_management": {
            "revisions": {
                "v7.2.4": True,
                "v7.2.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
            },
            "type": "string",
            "options": [
                {
                    "value": "allow",
                    "revisions": {
                        "v7.2.4": True,
                        "v7.2.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                    },
                },
                {
                    "value": "deny",
                    "revisions": {
                        "v7.2.4": True,
                        "v7.2.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                    },
                },
            ],
        },
        "version_not_support": {
            "revisions": {
                "v7.2.4": True,
                "v7.2.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
            },
            "type": "string",
            "options": [
                {
                    "value": "allow",
                    "revisions": {
                        "v7.2.4": True,
                        "v7.2.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                    },
                },
                {
                    "value": "deny",
                    "revisions": {
                        "v7.2.4": True,
                        "v7.2.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                    },
                },
            ],
        },
        "session_establish": {
            "revisions": {
                "v7.2.4": True,
                "v7.2.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
            },
            "type": "string",
            "options": [
                {
                    "value": "allow",
                    "revisions": {
                        "v7.2.4": True,
                        "v7.2.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                    },
                },
                {
                    "value": "deny",
                    "revisions": {
                        "v7.2.4": True,
                        "v7.2.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                    },
                },
            ],
        },
        "session_modification": {
            "revisions": {
                "v7.2.4": True,
                "v7.2.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
            },
            "type": "string",
            "options": [
                {
                    "value": "allow",
                    "revisions": {
                        "v7.2.4": True,
                        "v7.2.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                    },
                },
                {
                    "value": "deny",
                    "revisions": {
                        "v7.2.4": True,
                        "v7.2.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                    },
                },
            ],
        },
        "session_deletion": {
            "revisions": {
                "v7.2.4": True,
                "v7.2.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
            },
            "type": "string",
            "options": [
                {
                    "value": "allow",
                    "revisions": {
                        "v7.2.4": True,
                        "v7.2.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                    },
                },
                {
                    "value": "deny",
                    "revisions": {
                        "v7.2.4": True,
                        "v7.2.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                    },
                },
            ],
        },
        "session_report": {
            "revisions": {
                "v7.2.4": True,
                "v7.2.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
            },
            "type": "string",
            "options": [
                {
                    "value": "allow",
                    "revisions": {
                        "v7.2.4": True,
                        "v7.2.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                    },
                },
                {
                    "value": "deny",
                    "revisions": {
                        "v7.2.4": True,
                        "v7.2.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                    },
                },
            ],
        },
        "association_setup": {
            "revisions": {
                "v7.2.4": True,
                "v7.2.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
            },
            "type": "string",
            "options": [
                {
                    "value": "allow",
                    "revisions": {
                        "v7.2.4": True,
                        "v7.2.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                    },
                },
                {
                    "value": "deny",
                    "revisions": {
                        "v7.2.4": True,
                        "v7.2.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                    },
                },
            ],
        },
        "association_update": {
            "revisions": {
                "v7.2.4": True,
                "v7.2.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
            },
            "type": "string",
            "options": [
                {
                    "value": "allow",
                    "revisions": {
                        "v7.2.4": True,
                        "v7.2.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                    },
                },
                {
                    "value": "deny",
                    "revisions": {
                        "v7.2.4": True,
                        "v7.2.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                    },
                },
            ],
        },
        "association_release": {
            "revisions": {
                "v7.2.4": True,
                "v7.2.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
            },
            "type": "string",
            "options": [
                {
                    "value": "allow",
                    "revisions": {
                        "v7.2.4": True,
                        "v7.2.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                    },
                },
                {
                    "value": "deny",
                    "revisions": {
                        "v7.2.4": True,
                        "v7.2.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                    },
                },
            ],
        },
        "node_report": {
            "revisions": {
                "v7.2.4": True,
                "v7.2.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
            },
            "type": "string",
            "options": [
                {
                    "value": "allow",
                    "revisions": {
                        "v7.2.4": True,
                        "v7.2.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                    },
                },
                {
                    "value": "deny",
                    "revisions": {
                        "v7.2.4": True,
                        "v7.2.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                    },
                },
            ],
        },
        "session_set_deletion": {
            "revisions": {
                "v7.2.4": True,
                "v7.2.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
            },
            "type": "string",
            "options": [
                {
                    "value": "allow",
                    "revisions": {
                        "v7.2.4": True,
                        "v7.2.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                    },
                },
                {
                    "value": "deny",
                    "revisions": {
                        "v7.2.4": True,
                        "v7.2.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                    },
                },
            ],
        },
    },
    "revisions": {
        "v7.2.4": True,
        "v7.2.0": True,
        "v7.0.5": True,
        "v7.0.4": True,
        "v7.0.3": True,
        "v7.0.2": True,
        "v7.0.1": True,
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
        "pfcp_message_filter": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["pfcp_message_filter"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["pfcp_message_filter"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "pfcp_message_filter"
        )

        is_error, has_changed, result, diff = fortios_pfcp(module.params, fos)

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

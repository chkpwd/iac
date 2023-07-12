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
module: fortios_report_theme
short_description: Report themes configuratio in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify report feature and theme category.
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
    report_theme:
        description:
            - Report themes configuration
        default: null
        type: dict
        suboptions:
            bullet_list_style:
                description:
                    - Bullet list style.
                type: str
            column_count:
                description:
                    - Report page column count.
                type: str
                choices:
                    - '1'
                    - '2'
                    - '3'
            default_html_style:
                description:
                    - Default HTML report style.
                type: str
            default_pdf_style:
                description:
                    - Default PDF report style.
                type: str
            graph_chart_style:
                description:
                    - Graph chart style.
                type: str
            heading1_style:
                description:
                    - Report heading style.
                type: str
            heading2_style:
                description:
                    - Report heading style.
                type: str
            heading3_style:
                description:
                    - Report heading style.
                type: str
            heading4_style:
                description:
                    - Report heading style.
                type: str
            hline_style:
                description:
                    - Horizontal line style.
                type: str
            image_style:
                description:
                    - Image style.
                type: str
            name:
                description:
                    - Report theme name.
                required: true
                type: str
            normal_text_style:
                description:
                    - Normal text style.
                type: str
            numbered_list_style:
                description:
                    - Numbered list style.
                type: str
            page_footer_style:
                description:
                    - Report page footer style.
                type: str
            page_header_style:
                description:
                    - Report page header style.
                type: str
            page_orient:
                description:
                    - Report page orientation.
                type: str
                choices:
                    - 'portrait'
                    - 'landscape'
            page_style:
                description:
                    - Report page style.
                type: str
            report_subtitle_style:
                description:
                    - Report subtitle style.
                type: str
            report_title_style:
                description:
                    - Report title style.
                type: str
            table_chart_caption_style:
                description:
                    - Table chart caption style.
                type: str
            table_chart_even_row_style:
                description:
                    - Table chart even row style.
                type: str
            table_chart_head_style:
                description:
                    - Table chart head row style.
                type: str
            table_chart_odd_row_style:
                description:
                    - Table chart odd row style.
                type: str
            table_chart_style:
                description:
                    - Table chart style.
                type: str
            toc_heading1_style:
                description:
                    - Table of contents heading style.
                type: str
            toc_heading2_style:
                description:
                    - Table of contents heading style.
                type: str
            toc_heading3_style:
                description:
                    - Table of contents heading style.
                type: str
            toc_heading4_style:
                description:
                    - Table of contents heading style.
                type: str
            toc_title_style:
                description:
                    - Table of contents title style.
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
  - name: Report themes configuration
    fortios_report_theme:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      report_theme:
        bullet_list_style: "<your_own_value>"
        column_count: "1"
        default_html_style: "<your_own_value>"
        default_pdf_style: "<your_own_value>"
        graph_chart_style: "<your_own_value>"
        heading1_style: "<your_own_value>"
        heading2_style: "<your_own_value>"
        heading3_style: "<your_own_value>"
        heading4_style: "<your_own_value>"
        hline_style: "<your_own_value>"
        image_style: "<your_own_value>"
        name: "default_name_14"
        normal_text_style: "<your_own_value>"
        numbered_list_style: "<your_own_value>"
        page_footer_style: "<your_own_value>"
        page_header_style: "<your_own_value>"
        page_orient: "portrait"
        page_style: "<your_own_value>"
        report_subtitle_style: "<your_own_value>"
        report_title_style: "<your_own_value>"
        table_chart_caption_style: "<your_own_value>"
        table_chart_even_row_style: "<your_own_value>"
        table_chart_head_style: "<your_own_value>"
        table_chart_odd_row_style: "<your_own_value>"
        table_chart_style: "<your_own_value>"
        toc_heading1_style: "<your_own_value>"
        toc_heading2_style: "<your_own_value>"
        toc_heading3_style: "<your_own_value>"
        toc_heading4_style: "<your_own_value>"
        toc_title_style: "<your_own_value>"

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


def filter_report_theme_data(json):
    option_list = [
        "bullet_list_style",
        "column_count",
        "default_html_style",
        "default_pdf_style",
        "graph_chart_style",
        "heading1_style",
        "heading2_style",
        "heading3_style",
        "heading4_style",
        "hline_style",
        "image_style",
        "name",
        "normal_text_style",
        "numbered_list_style",
        "page_footer_style",
        "page_header_style",
        "page_orient",
        "page_style",
        "report_subtitle_style",
        "report_title_style",
        "table_chart_caption_style",
        "table_chart_even_row_style",
        "table_chart_head_style",
        "table_chart_odd_row_style",
        "table_chart_style",
        "toc_heading1_style",
        "toc_heading2_style",
        "toc_heading3_style",
        "toc_heading4_style",
        "toc_title_style",
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


def report_theme(data, fos, check_mode=False):

    vdom = data["vdom"]

    state = data["state"]

    report_theme_data = data["report_theme"]
    filtered_data = underscore_to_hyphen(filter_report_theme_data(report_theme_data))

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("report", "theme", filtered_data, vdom=vdom)
        current_data = fos.get("report", "theme", vdom=vdom, mkey=mkey)
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
        return fos.set("report", "theme", data=filtered_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("report", "theme", mkey=filtered_data["name"], vdom=vdom)
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


def fortios_report(data, fos, check_mode):

    fos.do_member_operation("report", "theme")
    if data["report_theme"]:
        resp = report_theme(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("report_theme"))
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
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
            "required": True,
        },
        "page_orient": {
            "revisions": {
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
            "options": [
                {
                    "value": "portrait",
                    "revisions": {
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
                {
                    "value": "landscape",
                    "revisions": {
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
            ],
        },
        "column_count": {
            "revisions": {
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
            "options": [
                {
                    "value": "1",
                    "revisions": {
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
                {
                    "value": "2",
                    "revisions": {
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
                {
                    "value": "3",
                    "revisions": {
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
            ],
        },
        "default_html_style": {
            "revisions": {
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "default_pdf_style": {
            "revisions": {
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "page_style": {
            "revisions": {
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "page_header_style": {
            "revisions": {
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "page_footer_style": {
            "revisions": {
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "report_title_style": {
            "revisions": {
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "report_subtitle_style": {
            "revisions": {
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "toc_title_style": {
            "revisions": {
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "toc_heading1_style": {
            "revisions": {
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "toc_heading2_style": {
            "revisions": {
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "toc_heading3_style": {
            "revisions": {
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "toc_heading4_style": {
            "revisions": {
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "heading1_style": {
            "revisions": {
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "heading2_style": {
            "revisions": {
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "heading3_style": {
            "revisions": {
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "heading4_style": {
            "revisions": {
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "normal_text_style": {
            "revisions": {
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "bullet_list_style": {
            "revisions": {
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "numbered_list_style": {
            "revisions": {
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "image_style": {
            "revisions": {
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "hline_style": {
            "revisions": {
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "graph_chart_style": {
            "revisions": {
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "table_chart_style": {
            "revisions": {
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "table_chart_caption_style": {
            "revisions": {
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "table_chart_head_style": {
            "revisions": {
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "table_chart_odd_row_style": {
            "revisions": {
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "table_chart_even_row_style": {
            "revisions": {
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
    },
    "revisions": {
        "v6.4.4": True,
        "v6.4.1": True,
        "v6.4.0": True,
        "v6.2.7": True,
        "v6.2.5": True,
        "v6.2.3": True,
        "v6.2.0": True,
        "v6.0.5": True,
        "v6.0.11": True,
        "v6.0.0": True,
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
        "report_theme": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["report_theme"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["report_theme"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "report_theme"
        )

        is_error, has_changed, result, diff = fortios_report(
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

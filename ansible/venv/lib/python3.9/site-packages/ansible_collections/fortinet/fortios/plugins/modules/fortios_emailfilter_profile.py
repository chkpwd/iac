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
module: fortios_emailfilter_profile
short_description: Configure Email Filter profiles in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify emailfilter feature and profile category.
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
    emailfilter_profile:
        description:
            - Configure Email Filter profiles.
        default: null
        type: dict
        suboptions:
            comment:
                description:
                    - Comment.
                type: str
            external:
                description:
                    - Enable/disable external Email inspection.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            feature_set:
                description:
                    - Flow/proxy feature set.
                type: str
                choices:
                    - 'flow'
                    - 'proxy'
            file_filter:
                description:
                    - File filter.
                type: dict
                suboptions:
                    entries:
                        description:
                            - File filter entries.
                        type: list
                        elements: dict
                        suboptions:
                            action:
                                description:
                                    - Action taken for matched file.
                                type: str
                                choices:
                                    - 'log'
                                    - 'block'
                            comment:
                                description:
                                    - Comment.
                                type: str
                            file_type:
                                description:
                                    - Select file type.
                                type: list
                                elements: dict
                                suboptions:
                                    name:
                                        description:
                                            - File type name. Source antivirus.filetype.name.
                                        required: true
                                        type: str
                            filter:
                                description:
                                    - Add a file filter.
                                required: true
                                type: str
                            password_protected:
                                description:
                                    - Match password-protected files.
                                type: str
                                choices:
                                    - 'yes'
                                    - 'any'
                            protocol:
                                description:
                                    - Protocols to apply with.
                                type: list
                                elements: str
                                choices:
                                    - 'smtp'
                                    - 'imap'
                                    - 'pop3'
                    log:
                        description:
                            - Enable/disable file filter logging.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    scan_archive_contents:
                        description:
                            - Enable/disable file filter archive contents scan.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    status:
                        description:
                            - Enable/disable file filter.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            gmail:
                description:
                    - Gmail.
                type: dict
                suboptions:
                    log:
                        description:
                            - Enable/disable logging.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    log_all:
                        description:
                            - Enable/disable logging of all email traffic.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
            imap:
                description:
                    - IMAP.
                type: dict
                suboptions:
                    action:
                        description:
                            - Action for spam email.
                        type: str
                        choices:
                            - 'pass'
                            - 'tag'
                    log:
                        description:
                            - Enable/disable logging.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    log_all:
                        description:
                            - Enable/disable logging of all email traffic.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    tag_msg:
                        description:
                            - Subject text or header added to spam email.
                        type: str
                    tag_type:
                        description:
                            - Tag subject or header for spam email.
                        type: list
                        elements: str
                        choices:
                            - 'subject'
                            - 'header'
                            - 'spaminfo'
            mapi:
                description:
                    - MAPI.
                type: dict
                suboptions:
                    action:
                        description:
                            - Action for spam email.
                        type: str
                        choices:
                            - 'pass'
                            - 'discard'
                    log:
                        description:
                            - Enable/disable logging.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    log_all:
                        description:
                            - Enable/disable logging of all email traffic.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
            msn_hotmail:
                description:
                    - MSN Hotmail.
                type: dict
                suboptions:
                    log:
                        description:
                            - Enable/disable logging.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    log_all:
                        description:
                            - Enable/disable logging of all email traffic.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
            name:
                description:
                    - Profile name.
                required: true
                type: str
            options:
                description:
                    - Options.
                type: list
                elements: str
                choices:
                    - 'bannedword'
                    - 'spambal'
                    - 'spamfsip'
                    - 'spamfssubmit'
                    - 'spamfschksum'
                    - 'spamfsurl'
                    - 'spamhelodns'
                    - 'spamraddrdns'
                    - 'spamrbl'
                    - 'spamhdrcheck'
                    - 'spamfsphish'
                    - 'spambwl'
            other_webmails:
                description:
                    - Other supported webmails.
                type: dict
                suboptions:
                    log_all:
                        description:
                            - Enable/disable logging of all email traffic.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
            pop3:
                description:
                    - POP3.
                type: dict
                suboptions:
                    action:
                        description:
                            - Action for spam email.
                        type: str
                        choices:
                            - 'pass'
                            - 'tag'
                    log:
                        description:
                            - Enable/disable logging.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    log_all:
                        description:
                            - Enable/disable logging of all email traffic.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    tag_msg:
                        description:
                            - Subject text or header added to spam email.
                        type: str
                    tag_type:
                        description:
                            - Tag subject or header for spam email.
                        type: list
                        elements: str
                        choices:
                            - 'subject'
                            - 'header'
                            - 'spaminfo'
            replacemsg_group:
                description:
                    - Replacement message group. Source system.replacemsg-group.name.
                type: str
            smtp:
                description:
                    - SMTP.
                type: dict
                suboptions:
                    action:
                        description:
                            - Action for spam email.
                        type: str
                        choices:
                            - 'pass'
                            - 'tag'
                            - 'discard'
                    hdrip:
                        description:
                            - Enable/disable SMTP email header IP checks for spamfsip, spamrbl, and spambal filters.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    local_override:
                        description:
                            - Enable/disable local filter to override SMTP remote check result.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    log:
                        description:
                            - Enable/disable logging.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    log_all:
                        description:
                            - Enable/disable logging of all email traffic.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    tag_msg:
                        description:
                            - Subject text or header added to spam email.
                        type: str
                    tag_type:
                        description:
                            - Tag subject or header for spam email.
                        type: list
                        elements: str
                        choices:
                            - 'subject'
                            - 'header'
                            - 'spaminfo'
            spam_bal_table:
                description:
                    - Anti-spam block/allow list table ID. Source emailfilter.block-allow-list.id.
                type: int
            spam_bwl_table:
                description:
                    - Anti-spam black/white list table ID. Source emailfilter.bwl.id.
                type: int
            spam_bword_table:
                description:
                    - Anti-spam banned word table ID. Source emailfilter.bword.id.
                type: int
            spam_bword_threshold:
                description:
                    - Spam banned word threshold.
                type: int
            spam_filtering:
                description:
                    - Enable/disable spam filtering.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            spam_iptrust_table:
                description:
                    - Anti-spam IP trust table ID. Source emailfilter.iptrust.id.
                type: int
            spam_log:
                description:
                    - Enable/disable spam logging for email filtering.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            spam_log_fortiguard_response:
                description:
                    - Enable/disable logging FortiGuard spam response.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            spam_mheader_table:
                description:
                    - Anti-spam MIME header table ID. Source emailfilter.mheader.id.
                type: int
            spam_rbl_table:
                description:
                    - Anti-spam DNSBL table ID. Source emailfilter.dnsbl.id.
                type: int
            yahoo_mail:
                description:
                    - Yahoo! Mail.
                type: dict
                suboptions:
                    log:
                        description:
                            - Enable/disable logging.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    log_all:
                        description:
                            - Enable/disable logging of all email traffic.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
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
  - name: Configure Email Filter profiles.
    fortios_emailfilter_profile:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      emailfilter_profile:
        comment: "Comment."
        external: "enable"
        feature_set: "flow"
        file_filter:
            entries:
             -
                action: "log"
                comment: "Comment."
                file_type:
                 -
                    name: "default_name_11 (source antivirus.filetype.name)"
                filter: "<your_own_value>"
                password_protected: "yes"
                protocol: "smtp"
            log: "enable"
            scan_archive_contents: "enable"
            status: "enable"
        gmail:
            log: "enable"
            log_all: "disable"
        imap:
            action: "pass"
            log: "enable"
            log_all: "disable"
            tag_msg: "<your_own_value>"
            tag_type: "subject"
        mapi:
            action: "pass"
            log: "enable"
            log_all: "disable"
        msn_hotmail:
            log: "enable"
            log_all: "disable"
        name: "default_name_34"
        options: "bannedword"
        other_webmails:
            log_all: "disable"
        pop3:
            action: "pass"
            log: "enable"
            log_all: "disable"
            tag_msg: "<your_own_value>"
            tag_type: "subject"
        replacemsg_group: "<your_own_value> (source system.replacemsg-group.name)"
        smtp:
            action: "pass"
            hdrip: "disable"
            local_override: "disable"
            log: "enable"
            log_all: "disable"
            tag_msg: "<your_own_value>"
            tag_type: "subject"
        spam_bal_table: "0"
        spam_bwl_table: "2147483647"
        spam_bword_table: "0"
        spam_bword_threshold: "10"
        spam_filtering: "enable"
        spam_iptrust_table: "0"
        spam_log: "disable"
        spam_log_fortiguard_response: "disable"
        spam_mheader_table: "0"
        spam_rbl_table: "0"
        yahoo_mail:
            log: "enable"
            log_all: "disable"

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


def filter_emailfilter_profile_data(json):
    option_list = [
        "comment",
        "external",
        "feature_set",
        "file_filter",
        "gmail",
        "imap",
        "mapi",
        "msn_hotmail",
        "name",
        "options",
        "other_webmails",
        "pop3",
        "replacemsg_group",
        "smtp",
        "spam_bal_table",
        "spam_bwl_table",
        "spam_bword_table",
        "spam_bword_threshold",
        "spam_filtering",
        "spam_iptrust_table",
        "spam_log",
        "spam_log_fortiguard_response",
        "spam_mheader_table",
        "spam_rbl_table",
        "yahoo_mail",
    ]

    json = remove_invalid_fields(json)
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def flatten_single_path(data, path, index):
    if (
        not data
        or index == len(path)
        or path[index] not in data
        or not data[path[index]]
    ):
        return

    if index == len(path) - 1:
        data[path[index]] = " ".join(str(elem) for elem in data[path[index]])
    elif isinstance(data[path[index]], list):
        for value in data[path[index]]:
            flatten_single_path(value, path, index + 1)
    else:
        flatten_single_path(data[path[index]], path, index + 1)


def flatten_multilists_attributes(data):
    multilist_attrs = [
        ["options"],
        ["imap", "tag_type"],
        ["pop3", "tag_type"],
        ["smtp", "tag_type"],
        ["file_filter", "entries", "protocol"],
    ]

    for attr in multilist_attrs:
        flatten_single_path(data, attr, 0)

    return data


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


def emailfilter_profile(data, fos, check_mode=False):

    vdom = data["vdom"]

    state = data["state"]

    emailfilter_profile_data = data["emailfilter_profile"]
    emailfilter_profile_data = flatten_multilists_attributes(emailfilter_profile_data)
    filtered_data = underscore_to_hyphen(
        filter_emailfilter_profile_data(emailfilter_profile_data)
    )

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("emailfilter", "profile", filtered_data, vdom=vdom)
        current_data = fos.get("emailfilter", "profile", vdom=vdom, mkey=mkey)
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
        return fos.set("emailfilter", "profile", data=filtered_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "emailfilter", "profile", mkey=filtered_data["name"], vdom=vdom
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


def fortios_emailfilter(data, fos, check_mode):

    fos.do_member_operation("emailfilter", "profile")
    if data["emailfilter_profile"]:
        resp = emailfilter_profile(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("emailfilter_profile"))
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
        "comment": {
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
        "feature_set": {
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
                "v6.2.7": False,
                "v6.2.5": False,
                "v6.2.3": False,
                "v6.2.0": False,
            },
            "type": "string",
            "options": [
                {
                    "value": "flow",
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
                    },
                },
                {
                    "value": "proxy",
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
                    },
                },
            ],
        },
        "replacemsg_group": {
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
        "spam_log": {
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
            "options": [
                {
                    "value": "disable",
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
                {
                    "value": "enable",
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
            ],
        },
        "spam_log_fortiguard_response": {
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
            "options": [
                {
                    "value": "disable",
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
                {
                    "value": "enable",
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
            ],
        },
        "spam_filtering": {
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
            "options": [
                {
                    "value": "enable",
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
                {
                    "value": "disable",
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
            ],
        },
        "external": {
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
            "options": [
                {
                    "value": "enable",
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
                {
                    "value": "disable",
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
            ],
        },
        "options": {
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
            "type": "list",
            "options": [
                {
                    "value": "bannedword",
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
                {
                    "value": "spambal",
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
                        "v6.4.4": False,
                        "v6.4.1": False,
                        "v6.4.0": False,
                        "v6.2.7": False,
                        "v6.2.5": False,
                        "v6.2.3": False,
                        "v6.2.0": False,
                    },
                },
                {
                    "value": "spamfsip",
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
                {
                    "value": "spamfssubmit",
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
                {
                    "value": "spamfschksum",
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
                {
                    "value": "spamfsurl",
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
                {
                    "value": "spamhelodns",
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
                {
                    "value": "spamraddrdns",
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
                {
                    "value": "spamrbl",
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
                {
                    "value": "spamhdrcheck",
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
                {
                    "value": "spamfsphish",
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
                {
                    "value": "spambwl",
                    "revisions": {
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                    },
                },
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "imap": {
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
            "type": "dict",
            "children": {
                "log_all": {
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
                        "v6.4.1": False,
                        "v6.4.0": True,
                        "v6.2.7": False,
                        "v6.2.5": False,
                        "v6.2.3": False,
                        "v6.2.0": False,
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
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
                                "v6.4.0": True,
                            },
                        },
                        {
                            "value": "enable",
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
                                "v6.4.0": True,
                            },
                        },
                    ],
                },
                "action": {
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
                    "options": [
                        {
                            "value": "pass",
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
                        {
                            "value": "tag",
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
                    ],
                },
                "tag_type": {
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
                    "type": "list",
                    "options": [
                        {
                            "value": "subject",
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
                        {
                            "value": "header",
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
                        {
                            "value": "spaminfo",
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
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "tag_msg": {
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
                "log": {
                    "revisions": {
                        "v6.4.1": True,
                        "v6.4.0": False,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.1": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.1": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                        },
                    ],
                },
            },
        },
        "pop3": {
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
            "type": "dict",
            "children": {
                "log_all": {
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
                        "v6.4.1": False,
                        "v6.4.0": True,
                        "v6.2.7": False,
                        "v6.2.5": False,
                        "v6.2.3": False,
                        "v6.2.0": False,
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
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
                                "v6.4.0": True,
                            },
                        },
                        {
                            "value": "enable",
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
                                "v6.4.0": True,
                            },
                        },
                    ],
                },
                "action": {
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
                    "options": [
                        {
                            "value": "pass",
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
                        {
                            "value": "tag",
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
                    ],
                },
                "tag_type": {
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
                    "type": "list",
                    "options": [
                        {
                            "value": "subject",
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
                        {
                            "value": "header",
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
                        {
                            "value": "spaminfo",
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
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "tag_msg": {
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
                "log": {
                    "revisions": {
                        "v6.4.1": True,
                        "v6.4.0": False,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.1": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.1": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                        },
                    ],
                },
            },
        },
        "smtp": {
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
            "type": "dict",
            "children": {
                "log_all": {
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
                        "v6.4.1": False,
                        "v6.4.0": True,
                        "v6.2.7": False,
                        "v6.2.5": False,
                        "v6.2.3": False,
                        "v6.2.0": False,
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
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
                                "v6.4.0": True,
                            },
                        },
                        {
                            "value": "enable",
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
                                "v6.4.0": True,
                            },
                        },
                    ],
                },
                "action": {
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
                    "options": [
                        {
                            "value": "pass",
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
                        {
                            "value": "tag",
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
                        {
                            "value": "discard",
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
                    ],
                },
                "tag_type": {
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
                    "type": "list",
                    "options": [
                        {
                            "value": "subject",
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
                        {
                            "value": "header",
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
                        {
                            "value": "spaminfo",
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
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "tag_msg": {
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
                "hdrip": {
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
                    "options": [
                        {
                            "value": "disable",
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
                        {
                            "value": "enable",
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
                    ],
                },
                "local_override": {
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
                    "options": [
                        {
                            "value": "disable",
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
                        {
                            "value": "enable",
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
                    ],
                },
                "log": {
                    "revisions": {
                        "v6.4.1": True,
                        "v6.4.0": False,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.1": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.1": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                        },
                    ],
                },
            },
        },
        "mapi": {
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
            "type": "dict",
            "children": {
                "log_all": {
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
                        "v6.4.1": False,
                        "v6.4.0": True,
                        "v6.2.7": False,
                        "v6.2.5": False,
                        "v6.2.3": False,
                        "v6.2.0": False,
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
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
                                "v6.4.0": True,
                            },
                        },
                        {
                            "value": "enable",
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
                                "v6.4.0": True,
                            },
                        },
                    ],
                },
                "action": {
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
                    "options": [
                        {
                            "value": "pass",
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
                        {
                            "value": "discard",
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
                    ],
                },
                "log": {
                    "revisions": {
                        "v6.4.1": True,
                        "v6.4.0": False,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.1": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.1": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                        },
                    ],
                },
            },
        },
        "msn_hotmail": {
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
            "type": "dict",
            "children": {
                "log_all": {
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
                        "v6.4.1": False,
                        "v6.4.0": True,
                        "v6.2.7": False,
                        "v6.2.5": False,
                        "v6.2.3": False,
                        "v6.2.0": False,
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
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
                                "v6.4.0": True,
                            },
                        },
                        {
                            "value": "enable",
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
                                "v6.4.0": True,
                            },
                        },
                    ],
                },
                "log": {
                    "revisions": {
                        "v6.4.1": True,
                        "v6.4.0": False,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.1": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.1": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                        },
                    ],
                },
            },
        },
        "yahoo_mail": {
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
            "type": "dict",
            "children": {
                "log_all": {
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
                        "v6.4.1": False,
                        "v6.4.0": True,
                        "v6.2.7": False,
                        "v6.2.5": False,
                        "v6.2.3": False,
                        "v6.2.0": False,
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
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
                                "v6.4.0": True,
                            },
                        },
                        {
                            "value": "enable",
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
                                "v6.4.0": True,
                            },
                        },
                    ],
                },
                "log": {
                    "revisions": {
                        "v6.4.1": True,
                        "v6.4.0": False,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.1": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.1": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                        },
                    ],
                },
            },
        },
        "gmail": {
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
            "type": "dict",
            "children": {
                "log_all": {
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
                        "v6.4.1": False,
                        "v6.4.0": True,
                        "v6.2.7": False,
                        "v6.2.5": False,
                        "v6.2.3": False,
                        "v6.2.0": False,
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
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
                                "v6.4.0": True,
                            },
                        },
                        {
                            "value": "enable",
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
                                "v6.4.0": True,
                            },
                        },
                    ],
                },
                "log": {
                    "revisions": {
                        "v6.4.1": True,
                        "v6.4.0": False,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.1": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.1": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                        },
                    ],
                },
            },
        },
        "other_webmails": {
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
                "v6.4.1": False,
                "v6.4.0": True,
                "v6.2.7": False,
                "v6.2.5": False,
                "v6.2.3": False,
                "v6.2.0": False,
            },
            "type": "dict",
            "children": {
                "log_all": {
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
                        "v6.4.0": True,
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
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
                                "v6.4.0": True,
                            },
                        },
                        {
                            "value": "enable",
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
                                "v6.4.0": True,
                            },
                        },
                    ],
                }
            },
        },
        "spam_bword_threshold": {
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
            "type": "integer",
        },
        "spam_bword_table": {
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
            "type": "integer",
        },
        "spam_bal_table": {
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
                "v6.4.4": False,
                "v6.4.1": False,
                "v6.4.0": False,
                "v6.2.7": False,
                "v6.2.5": False,
                "v6.2.3": False,
                "v6.2.0": False,
            },
            "type": "integer",
        },
        "spam_mheader_table": {
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
            "type": "integer",
        },
        "spam_rbl_table": {
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
            "type": "integer",
        },
        "spam_iptrust_table": {
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
            "type": "integer",
        },
        "spam_bwl_table": {
            "revisions": {
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
            },
            "type": "integer",
        },
        "file_filter": {
            "revisions": {
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
            },
            "type": "dict",
            "children": {
                "status": {
                    "revisions": {
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                        },
                    ],
                },
                "log": {
                    "revisions": {
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                        },
                    ],
                },
                "scan_archive_contents": {
                    "revisions": {
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                        },
                    ],
                },
                "entries": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "filter": {
                            "revisions": {
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                            "type": "string",
                            "required": True,
                        },
                        "comment": {
                            "revisions": {
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                            "type": "string",
                        },
                        "protocol": {
                            "revisions": {
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                            "type": "list",
                            "options": [
                                {
                                    "value": "smtp",
                                    "revisions": {
                                        "v6.2.7": True,
                                        "v6.2.5": True,
                                        "v6.2.3": True,
                                        "v6.2.0": True,
                                    },
                                },
                                {
                                    "value": "imap",
                                    "revisions": {
                                        "v6.2.7": True,
                                        "v6.2.5": True,
                                        "v6.2.3": True,
                                        "v6.2.0": True,
                                    },
                                },
                                {
                                    "value": "pop3",
                                    "revisions": {
                                        "v6.2.7": True,
                                        "v6.2.5": True,
                                        "v6.2.3": True,
                                        "v6.2.0": True,
                                    },
                                },
                            ],
                            "multiple_values": True,
                            "elements": "str",
                        },
                        "action": {
                            "revisions": {
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                            "type": "string",
                            "options": [
                                {
                                    "value": "log",
                                    "revisions": {
                                        "v6.2.7": True,
                                        "v6.2.5": True,
                                        "v6.2.3": True,
                                        "v6.2.0": True,
                                    },
                                },
                                {
                                    "value": "block",
                                    "revisions": {
                                        "v6.2.7": True,
                                        "v6.2.5": True,
                                        "v6.2.3": True,
                                        "v6.2.0": True,
                                    },
                                },
                            ],
                        },
                        "password_protected": {
                            "revisions": {
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                            "type": "string",
                            "options": [
                                {
                                    "value": "yes",
                                    "revisions": {
                                        "v6.2.7": True,
                                        "v6.2.5": True,
                                        "v6.2.3": True,
                                        "v6.2.0": True,
                                    },
                                },
                                {
                                    "value": "any",
                                    "revisions": {
                                        "v6.2.7": True,
                                        "v6.2.5": True,
                                        "v6.2.3": True,
                                        "v6.2.0": True,
                                    },
                                },
                            ],
                        },
                        "file_type": {
                            "type": "list",
                            "elements": "dict",
                            "children": {
                                "name": {
                                    "revisions": {
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
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                        },
                    },
                    "revisions": {
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                    },
                },
            },
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
        "emailfilter_profile": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["emailfilter_profile"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["emailfilter_profile"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "emailfilter_profile"
        )

        is_error, has_changed, result, diff = fortios_emailfilter(
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

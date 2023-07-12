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
description: Manage an HPE Nimble Storage group on an Nimble Storage array.
module: hpe_nimble_group
options:
  alarms:
    required: False
    type: bool
    description:
    - Whether alarm feature is enabled.
  alert_to_email_addrs:
    required: False
    type: str
    description:
    - Comma-separated list of email addresses to receive emails. Comma separated email list.
  alert_from_email_addrs:
    required: False
    type: str
    description:
    - From email address to use while sending emails. Case insensitive email address.
  alert_min_level:
    required: False
    choices:
      - info
      - notice
      - warning
      - critical
    type: str
    description:
    - Minimum level of alert to be notified.
  allow_analytics_gui:
    required: False
    type: bool
    description:
    - Specify whether to allow HPE Nimble Storage to use Google Analytics in the GUI. HPE Nimble Storage uses Google Analytics
      to gather data related to GUI usage. The data gathered is used to evaluate and improve the product.
  allow_support_tunnel:
    required: False
    type: bool
    description:
    - Whether to allow support tunnel.
  auto_switchover:
    required: False
    type: bool
    description:
    - Whether automatic switchover of Group management services feature is enabled.
  autoclean_unmanaged_snapshots:
    required: False
    type: bool
    description:
    - Whether autoclean unmanaged snapshots feature is enabled.
  autoclean_unmanaged_snapshots_ttl_unit:
    required: False
    type: int
    description:
    - Unit for unmanaged snapshot time to live.
  autosupport:
    required: False
    type: bool
    description:
    - Whether to send autosupport.
  cc_mode:
    required: False
    type: bool
    description:
    - Enable or disable Common Criteria mode.
  change_name:
    required: False
    type: str
    description:
    - Change name of the existing group.
  check_migrate:
    required: False
    type: bool
    description:
    - Check if the group Management Service can be migrated to the group Management Service backup array.
  date:
    required: False
    type: int
    description:
    - Unix epoch time local to the group. Seconds since last epoch. Example- 3400.
  default_iscsi_target_scope:
    required: False
    choices:
    - volume
    - group
    type: str
    description:
    - Newly created volumes are exported under iSCSI Group Target or iSCSI Volume Target.
  default_volume_limit:
    required: False
    type: int
    description:
    - Default limit for a volume space usage as a percentage of volume size. Volume will be taken offline/made non-writable on exceeding its
      limit. Percentage as integer from 0 to 100.
  domain_name:
    required: False
    type: str
    description:
    - Domain name for this group. String of alphanumeric characters, valid range is from 2 to 255; Each label must be between 1 and 63 characters
      long; - and . are allowed after the first and before the last character.
  dns_servers:
    required: False
    type: list
    elements: dict
    description:
    - IP addresses for this group's dns servers.
  fc_enabled:
    required: False
    type: bool
    description:
    - Whether FC is enabled on this group.
  force:
    required: False
    type: bool
    default: False
    description:
    - Can be used with halt or merge flag. Halt remaining arrays when one or more is unreachable.
      Ignore warnings and forcibly merge specified group with this group.
  group_snapshot_ttl:
    required: False
    type: int
    description:
    - Snapshot Time-to-live(TTL) configured at group level for automatic deletion of unmanaged snapshots. Value 0 indicates unlimited TTL.
  group_target_enabled:
    required: False
    type: bool
    description:
    - Is group_target enabled on this group.
  group_target_name:
    required: False
    type: str
    description:
    - Iscsi target name for this group. String of up to 255 alphanumeric, hyphenated, colon, or period-separated characters;
      but cannot begin with hyphen, colon or period. This type is used for the group target name.
  halt:
    required: False
    type: bool
    description:
    - Halt all arrays in the group.
  iscsi_enabled:
    required: False
    type: bool
    description:
    - Whether iSCSI is enabled on this group.
  isns_enabled:
    required: False
    type: bool
    description:
    - Whether iSNS is enabled.
  isns_port:
    required: False
    type: int
    description:
    - Port number for iSNS Server. Positive integer value up to 65535 representing TCP/IP port.
  isns_server:
    required: False
    type: str
    description:
    - Hostname or IP Address of iSNS Server.
  level:
    required: False
    choices:
    - info
    - notice
    - warning
    - critical
    type: str
    description:
    - Level of the test alert.
  login_banner_after_auth:
    required: False
    type: bool
    description:
    - Should the banner be displayed before the user credentials are prompted or after prompting the user credentials.
  login_banner_message:
    required: False
    type: str
    description:
    - The message for the login banner that is displayed during user login activity. String upto 2048 characters.
  login_banner_reset:
    required: False
    type: str
    description:
    - This will reset the banner to the version of the installed NOS. When login_banner_after_auth is specified, login_banner_reset can not be set to true.
  merge:
    required: False
    type: bool
    description:
    - Perform group merge with the specified group.
  migrate:
    required: False
    type: bool
    description:
    - Migrate the group Management Service to the current group Management Service backup array.
  name:
    required: True
    type: str
    description:
    - Name of the group.
  ntp_server:
    required: False
    type: str
    description:
    - Either IP address or hostname of the NTP server for this group. Plain string.
  proxy_port:
    required: False
    type: int
    description:
    - Proxy Port of HTTP Proxy Server. Integer value between 0-65535 representing TCP/IP port.
  proxy_server:
    required: False
    type: str
    description:
    - Hostname or IP Address of HTTP Proxy Server. Setting this attribute to an empty string will unset all proxy settings.
  proxy_username:
    required: False
    type: str
    description:
    - Username to authenticate with HTTP Proxy Server. HTTP proxy server username, string up to 255 characters, special
    - characters ([, ], `, ;, ampersand, tab, space, newline) are not allowed.
  proxy_password:
    required: False
    type: str
    description:
    - Password to authenticate with HTTP Proxy Server.
  reboot:
    required: False
    type: bool
    description:
    - Reboot all arrays in the group.
  repl_throttle_list:
    required: False
    type: list
    elements: dict
    description:
    - All the replication bandwidth limits on the system. All the throttles for the partner.
  send_alert_to_support:
    required: False
    type: bool
    description:
    - Whether to send alert to Support.
  skip_secondary_mgmt_ip:
    required: False
    type: bool
    description:
    - Skip check for secondary management IP address.
  smtp_auth_enabled:
    required: False
    type: bool
    description:
    - Whether SMTP Server requires authentication.
  smtp_auth_password:
    required: False
    type: str
    description:
    - Password to authenticate with SMTP Server.
  smtp_auth_username:
    required: False
    type: str
    description:
    - Username to authenticate with SMTP Server.
  smtp_port:
    required: False
    type: int
    description:
    - Port number of SMTP Server.
  smtp_encrypt_type:
    required: False
    choices:
    - none
    - starttls
    - ssl
    type: str
    description:
    - Level of encryption for SMTP.
  snmp_community:
    required: False
    type: str
    description:
    - Community string to be used with SNMP.
  snmp_get_enabled:
    required: False
    type: bool
    description:
    - Whether to accept SNMP get commands.
  snmp_get_port:
    required: False
    type: int
    description:
    - Port number to which SNMP get requests should be sent.
  snmp_trap_enabled:
    required: False
    type: bool
    description:
    - Whether to enable SNMP traps.
  snmp_trap_host:
    required: False
    type: str
    description:
    - Hostname or IP Address to send SNMP traps.
  snmp_trap_port:
    required: False
    type: int
    description:
    - Port number of SNMP trap host.
  snmp_sys_contact:
    required: False
    type: str
    description:
    - Name of the SNMP administrator. Plain string.
  snmp_sys_location:
    required: False
    type: str
    description:
    - Location of the group. Plain string.
  src_group_ip:
    required: False
    type: str
    description:
    - IP address of the source group.
  src_group_name:
    required: False
    type: str
    description:
    - Name of the source group.
  src_username:
    required: False
    type: str
    description:
    - Username of the source group.
  src_passphrase:
    required: False
    type: str
    description:
    - Source group encryption passphrase. Encryption passphrase. String with size from 8 to 64 printable characters.
  src_password:
    required: False
    type: str
    description:
    - Password of the source group.
  state:
    required: True
    choices:
    - present
    - absent
    type: str
    description:
    - The group operation.
  syslogd_enabled:
    required: False
    type: bool
    description:
    - Is syslogd enabled on this system.
  syslogd_port:
    required: False
    type: int
    description:
    - Port number for syslogd server.
  syslogd_server:
    required: False
    type: str
    description:
    - Hostname of the syslogd server.
  tdz_enabled:
    required: False
    type: bool
    description:
    - Is Target Driven Zoning (TDZ) enabled on this group.
  tdz_prefix:
    required: False
    type: str
    description:
    - Target Driven Zoning (TDZ) prefix for peer zones created by TDZ.
  test_alert:
    required: False
    type: bool
    description:
    - Generate a test alert.
  timezone:
    required: False
    type: str
    description:
    - Timezone in which this group is located. Plain string.
  tlsv1_enabled:
    required: False
    type: bool
    description:
    - Enable or disable TLSv1.0 and TLSv1.1.
  user_inactivity_timeout:
    required: False
    type: int
    description:
    - The amount of time in seconds that the user session is inactive before timing out. User inactivity timeout in second, valid range is from 1 to 43200.
  validate_merge:
    required: False
    type: bool
    description:
    - Perform group merge validation.
  vss_validation_timeout:
    required: False
    type: int
    description:
    - The amount of time in seconds to validate Microsoft VSS application synchronization before timing out. VSS validation timeout in second,
      valid range is from 1 to 3600.
  vvol_enabled:
    required: False
    type: bool
    description:
    - Are vVol enabled on this group.
extends_documentation_fragment: hpe.nimble.hpe_nimble
short_description: Manage the HPE Nimble Storage group
version_added: "1.0.0"
notes:
  - This module does not support C(check_mode).
'''

EXAMPLES = r'''

- name: Update group
  hpe.nimble.hpe_nimble_group:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "{{ name }}"
    send_alert_to_support: "{{ send_alert_to_support }}"
    alert_to_email_addrs: "{{ alert_to_email_addrs }}"
    state: "present"

- name: Reboot group
  hpe.nimble.hpe_nimble_group:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "{{ name }}"
    state: "present"
    reboot: true

- name: Halt group
  hpe.nimble.hpe_nimble_group:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "{{ name }}"
    state: "present"
    halt: true

- name: Validate merge group
  hpe.nimble.hpe_nimble_group:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "{{ name }}"
    src_group_ip: "{{ src_group_ip }}"
    src_password: "{{ src_password }}"
    skip_secondary_mgmt_ip: "{{ skip_secondary_mgmt_ip }}"
    src_passphrase: "{{ src_passphrase }}"
    state: "present"
    validate_merge: true

- name: Merge group
  hpe.nimble.hpe_nimble_group:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "{{ name }}"
    src_group_ip: "{{ src_group_ip }}"
    src_password: "{{ src_password }}"
    skip_secondary_mgmt_ip: "{{ skip_secondary_mgmt_ip }}"
    src_passphrase: "{{ src_passphrase }}"
    state: "present"
    merge: true

- name: Test alert group
  hpe.nimble.hpe_nimble_group:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "{{ name }}"
    level: "{{ level }}"
    state: "present"
    test_alert: true

- name: Migrate group
  hpe.nimble.hpe_nimble_group:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "{{ name }}"
    state: "present"
    migrate: true

- name: Check migrate group
  hpe.nimble.hpe_nimble_group:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "{{ name }}"
    state: "present"
    check_migrate: true

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


def update_group(
        client_obj,
        group_name,
        **kwargs):

    if utils.is_null_or_empty(group_name):
        return (False, False, "Update group failed as it is not present.", {}, {})

    try:
        group_resp = client_obj.groups.get(id=None, name=group_name)
        if utils.is_null_or_empty(group_resp):
            return (False, False, f"Group '{group_name}' cannot be updated as it is not present.", {}, {})

        changed_attrs_dict, params = utils.remove_unchanged_or_null_args(group_resp, **kwargs)
        if changed_attrs_dict.__len__() > 0:
            group_resp = client_obj.groups.update(id=group_resp.attrs.get("id"), **params)
            return (True, True, f"Group '{group_name}' already present. Modified the following attributes '{changed_attrs_dict}'",
                    changed_attrs_dict, group_resp.attrs)
        else:
            return (True, False, f"Group '{group_resp.attrs.get('name')}' already present in given state.", {}, group_resp.attrs)
    except Exception as ex:
        return (False, False, f"Group update failed | '{ex}'", {}, {})


def reboot_group(
        client_obj,
        group_name):

    if utils.is_null_or_empty(group_name):
        return (False, False, "Reboot group failed as it is not present.", {})

    try:
        group_resp = client_obj.groups.get(id=None, name=group_name)
        if utils.is_null_or_empty(group_resp):
            return (False, False, f"Group '{group_name}' cannot be rebooted as it is not present.", {})

        client_obj.groups.reboot(id=group_resp.attrs.get("id"))
        return (True, True, f"Rebooted group '{group_name}' successfully.", {})
    except Exception as ex:
        return (False, False, f"Reboot group failed | '{ex}'", {})


def halt_group(
        client_obj,
        group_name,
        **kwargs):

    if utils.is_null_or_empty(group_name):
        return (False, False, "Halt group failed as it is not present.", {})

    try:
        group_resp = client_obj.groups.get(id=None, name=group_name)
        if utils.is_null_or_empty(group_resp):
            return (False, False, f"Group '{group_name}' cannot be halted as it is not present.", {})
        params = utils.remove_null_args(**kwargs)
        client_obj.groups.halt(id=group_resp.attrs.get("id"), **params)
        return (True, True, f"Halted group '{group_name}' successfully.", {})
    except Exception as ex:
        return (False, False, f"Halt group failed | '{ex}'", {})


def test_alert_group(
        client_obj,
        group_name,
        level):

    if utils.is_null_or_empty(group_name):
        return (False, False, "Test alert for group failed as it is not present.", {})

    try:
        group_resp = client_obj.groups.get(id=None, name=group_name)
        if utils.is_null_or_empty(group_resp):
            return (False, False, f"Test alert for group '{group_name}' cannot be done as it is not present.", {})

        client_obj.groups.test_alert(id=group_resp.attrs.get("id"), level=level)
        return (True, True, f"Tested alert for group '{group_name}' successfully.", {})
    except Exception as ex:
        return (False, False, f"Test alert for group failed | '{ex}'", {})


def validate_merge_group(
        client_obj,
        group_name,
        **kwargs):

    if utils.is_null_or_empty(group_name):
        return (False, False, "Validate merge for group failed as it is not present.", {}, {})
    try:

        group_resp = client_obj.groups.get(id=None, name=group_name)
        if utils.is_null_or_empty(group_resp):
            return (False, False, f"Validate merge for group '{group_name}' cannot be done as it is not present.", {}, {})

        params = utils.remove_null_args(**kwargs)
        validate_merge_resp = client_obj.groups.validate_merge(id=group_resp.attrs.get("id"), **params)

        if hasattr(validate_merge_resp, 'attrs'):
            validate_merge_resp = validate_merge_resp.attrs

        if utils.is_null_or_empty(validate_merge_resp.get("validation_error_msg")):
            return (True, False, f"Validate merge operation for group '{group_name}' done successfully.", {}, validate_merge_resp)
        else:
            msg = validate_merge_resp.get("validation_error_msg")
            return (False, False, f"Validate merge operation for group '{group_name}' failed with error '{msg}'", {}, validate_merge_resp)
    except Exception as ex:
        return (False, False, f"Validate merge for group failed | '{ex}'", {}, {})


def merge_group(
        client_obj,
        group_name,
        **kwargs):

    if utils.is_null_or_empty(group_name):
        return (False, False, "Merge for group failed as it is not present.", {}, {})
    try:
        group_resp = client_obj.groups.get(id=None, name=group_name)
        if utils.is_null_or_empty(group_resp):
            return (False, False, f"Merge for group '{group_name}' cannot be done as it is not present.", {}, {})

        params = utils.remove_null_args(**kwargs)
        merge_resp = client_obj.groups.merge(id=group_resp.attrs.get("id"), **params)

        if hasattr(merge_resp, 'attrs'):
            merge_resp = merge_resp.attrs
        return (True, True, f"Merged group '{group_name}' successfully.", {}, merge_resp)
    except Exception as ex:
        return (False, False, f"Merge for group failed | '{ex}'", {}, {})


def check_migrate_group(
        client_obj,
        group_name):

    if utils.is_null_or_empty(group_name):
        return (False, False, "Check migrate for group failed as it is not present.", {})

    try:
        group_resp = client_obj.groups.get(id=None, name=group_name)
        if utils.is_null_or_empty(group_resp):
            return (False, False, f"Check migrate for group '{group_name}' cannot be done as it is not present.", {})

        client_obj.groups.check_migrate(id=group_resp.attrs.get("id"))
        return (True, True, f"Check migrate for group '{group_name}' done successfully.", {})
    except Exception as ex:
        return (False, False, f"Check migrate for group failed | '{ex}'", {})


def migrate_group(
        client_obj,
        group_name):

    if utils.is_null_or_empty(group_name):
        return (False, False, "Group migrate failed as it is not present.", {})

    try:
        group_resp = client_obj.groups.get(id=None, name=group_name)
        if utils.is_null_or_empty(group_resp):
            return (False, False, f"Migrate for group '{group_name}' cannot be done as it is not present.", {})

        client_obj.groups.migrate(id=group_resp.attrs.get("id"))
        return (True, True, f"Group '{group_name}' migrated successfully.", {})
    except Exception as ex:
        return (False, False, f"Group migrate failed | '{ex}'", {})


def main():

    fields = {
        "alarms": {
            "required": False,
            "type": "bool"
        },
        "alert_to_email_addrs": {
            "required": False,
            "type": "str"
        },
        "alert_from_email_addrs": {
            "required": False,
            "type": "str"
        },
        "alert_min_level": {
            "required": False,
            "choices": ['info',
                        'notice',
                        'warning',
                        'critical'
                        ],
            "type": "str"
        },
        "allow_analytics_gui": {
            "required": False,
            "type": "bool"
        },
        "allow_support_tunnel": {
            "required": False,
            "type": "bool"
        },
        "auto_switchover": {
            "required": False,
            "type": "bool"
        },
        "autoclean_unmanaged_snapshots": {
            "required": False,
            "type": "bool"
        },
        "autoclean_unmanaged_snapshots_ttl_unit": {
            "required": False,
            "type": "int"
        },
        "autosupport": {
            "required": False,
            "type": "bool"
        },
        "cc_mode": {
            "required": False,
            "type": "bool"
        },
        "change_name": {
            "required": False,
            "type": "str"
        },
        "check_migrate": {
            "required": False,
            "type": "bool"
        },
        "date": {
            "required": False,
            "type": "int"
        },
        "default_iscsi_target_scope": {
            "required": False,
            "choices": ['volume',
                        'group'
                        ],
            "type": "str"
        },
        "default_volume_limit": {
            "required": False,
            "type": "int"
        },
        "domain_name": {
            "required": False,
            "type": "str"
        },
        "dns_servers": {
            "required": False,
            "type": "list",
            "elements": 'dict'
        },
        "fc_enabled": {
            "required": False,
            "type": "bool"
        },
        "force": {
            "required": False,
            "type": "bool",
            "default": False
        },
        "group_snapshot_ttl": {
            "required": False,
            "type": "int"
        },
        "group_target_enabled": {
            "required": False,
            "type": "bool"
        },
        "group_target_name": {
            "required": False,
            "type": "str"
        },
        "halt": {
            "required": False,
            "type": "bool"
        },
        "iscsi_enabled": {
            "required": False,
            "type": "bool"
        },
        "isns_enabled": {
            "required": False,
            "type": "bool"
        },
        "isns_port": {
            "required": False,
            "type": "int"
        },
        "isns_server": {
            "required": False,
            "type": "str"
        },
        "level": {
            "required": False,
            "choices": ['info',
                        'notice',
                        'warning',
                        'critical'
                        ],
            "type": "str"
        },
        "login_banner_after_auth": {
            "required": False,
            "type": "bool"
        },
        "login_banner_message": {
            "required": False,
            "type": "str"
        },
        "login_banner_reset": {
            "required": False,
            "type": "str"
        },
        "merge": {
            "required": False,
            "type": "bool"
        },
        "migrate": {
            "required": False,
            "type": "bool"
        },
        "name": {
            "required": True,
            "type": "str"
        },
        "ntp_server": {
            "required": False,
            "type": "str"
        },
        "proxy_port": {
            "required": False,
            "type": "int"
        },
        "proxy_server": {
            "required": False,
            "type": "str"
        },
        "proxy_username": {
            "required": False,
            "type": "str"
        },
        "proxy_password": {
            "required": False,
            "type": "str",
            "no_log": True
        },
        "reboot": {
            "required": False,
            "type": "bool"
        },
        "repl_throttle_list": {
            "required": False,
            "type": "list",
            "elements": 'dict'
        },
        "send_alert_to_support": {
            "required": False,
            "type": "bool"
        },
        "skip_secondary_mgmt_ip": {
            "required": False,
            "type": "bool"
        },
        "smtp_auth_enabled": {
            "required": False,
            "type": "bool"
        },
        "smtp_auth_password": {
            "required": False,
            "type": "str",
            "no_log": True
        },
        "smtp_auth_username": {
            "required": False,
            "type": "str"
        },
        "smtp_port": {
            "required": False,
            "type": "int"
        },
        "smtp_encrypt_type": {
            "required": False,
            "choices": ['none',
                        'starttls',
                        'ssl'
                        ],
            "type": "str"
        },
        "snmp_community": {
            "required": False,
            "type": "str"
        },
        "snmp_get_enabled": {
            "required": False,
            "type": "bool"
        },
        "snmp_get_port": {
            "required": False,
            "type": "int"
        },
        "snmp_trap_enabled": {
            "required": False,
            "type": "bool"
        },
        "snmp_trap_host": {
            "required": False,
            "type": "str"
        },
        "snmp_trap_port": {
            "required": False,
            "type": "int"
        },
        "snmp_sys_contact": {
            "required": False,
            "type": "str"
        },
        "snmp_sys_location": {
            "required": False,
            "type": "str"
        },
        "src_group_ip": {
            "required": False,
            "type": "str"
        },
        "src_group_name": {
            "required": False,
            "type": "str"
        },
        "src_username": {
            "required": False,
            "type": "str"
        },
        "src_passphrase": {
            "required": False,
            "type": "str",
            "no_log": True
        },
        "src_password": {
            "required": False,
            "type": "str",
            "no_log": True
        },
        "state": {
            "required": True,
            "choices": ['present',
                        'absent'
                        ],
            "type": "str"
        },
        "syslogd_enabled": {
            "required": False,
            "type": "bool"
        },
        "syslogd_port": {
            "required": False,
            "type": "int"
        },
        "syslogd_server": {
            "required": False,
            "type": "str"
        },
        "tdz_enabled": {
            "required": False,
            "type": "bool"
        },
        "tdz_prefix": {
            "required": False,
            "type": "str"
        },
        "test_alert": {
            "required": False,
            "type": "bool"
        },
        "timezone": {
            "required": False,
            "type": "str"
        },
        "tlsv1_enabled": {
            "required": False,
            "type": "bool"
        },
        "user_inactivity_timeout": {
            "required": False,
            "type": "int"
        },
        "validate_merge": {
            "required": False,
            "type": "bool"
        },
        "vss_validation_timeout": {
            "required": False,
            "type": "int"
        },
        "vvol_enabled": {
            "required": False,
            "type": "bool"
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
    alarms = module.params["alarms"]
    alert_to_email_addrs = module.params["alert_to_email_addrs"]
    alert_from_email_addrs = module.params["alert_from_email_addrs"]
    alert_min_level = module.params["alert_min_level"]
    allow_analytics_gui = module.params["allow_analytics_gui"]
    allow_support_tunnel = module.params["allow_support_tunnel"]
    auto_switchover = module.params["auto_switchover"]
    autoclean_unmanaged_snapshots = module.params["autoclean_unmanaged_snapshots"]
    autoclean_unmanaged_snapshots_ttl_unit = module.params["autoclean_unmanaged_snapshots_ttl_unit"]
    autosupport = module.params["autosupport"]
    cc_mode = module.params["cc_mode"]
    change_name = module.params["change_name"]
    check_migrate = module.params["check_migrate"]
    date = module.params["date"]
    default_iscsi_target_scope = module.params["default_iscsi_target_scope"]
    default_volume_limit = module.params["default_volume_limit"]
    domain_name = module.params["domain_name"]
    dns_servers = module.params["dns_servers"]
    fc_enabled = module.params["fc_enabled"]
    force = module.params["force"]
    group_snapshot_ttl = module.params["group_snapshot_ttl"]
    group_target_enabled = module.params["group_target_enabled"]
    group_target_name = module.params["group_target_name"]
    halt = module.params["halt"]
    iscsi_enabled = module.params["iscsi_enabled"]
    isns_enabled = module.params["isns_enabled"]
    isns_port = module.params["isns_port"]
    isns_server = module.params["isns_server"]
    level = module.params["level"]
    login_banner_after_auth = module.params["login_banner_after_auth"]
    login_banner_message = module.params["login_banner_message"]
    login_banner_reset = module.params["login_banner_reset"]
    merge = module.params["merge"]
    migrate = module.params["migrate"]
    group_name = module.params["name"]
    ntp_server = module.params["ntp_server"]
    proxy_port = module.params["proxy_port"]
    proxy_server = module.params["proxy_server"]
    proxy_username = module.params["proxy_username"]
    proxy_password = module.params["proxy_password"]
    reboot = module.params["reboot"]
    repl_throttle_list = module.params["repl_throttle_list"]
    send_alert_to_support = module.params["send_alert_to_support"]
    skip_secondary_mgmt_ip = module.params["skip_secondary_mgmt_ip"]
    smtp_auth_enabled = module.params["smtp_auth_enabled"]
    smtp_auth_password = module.params["smtp_auth_password"]
    smtp_auth_username = module.params["smtp_auth_username"]
    smtp_port = module.params["smtp_port"]
    smtp_encrypt_type = module.params["smtp_encrypt_type"]
    snmp_community = module.params["snmp_community"]
    snmp_get_enabled = module.params["snmp_get_enabled"]
    snmp_get_port = module.params["snmp_get_port"]
    snmp_trap_enabled = module.params["snmp_trap_enabled"]
    snmp_trap_host = module.params["snmp_trap_host"]
    snmp_trap_port = module.params["snmp_trap_port"]
    snmp_sys_contact = module.params["snmp_sys_contact"]
    snmp_sys_location = module.params["snmp_sys_location"]
    src_group_ip = module.params["src_group_ip"]
    src_group_name = module.params["src_group_name"]
    src_username = module.params["src_username"]
    src_passphrase = module.params["src_passphrase"]
    src_password = module.params["src_password"]
    state = module.params["state"]
    syslogd_enabled = module.params["syslogd_enabled"]
    syslogd_port = module.params["syslogd_port"]
    syslogd_server = module.params["syslogd_server"]
    tdz_enabled = module.params["tdz_enabled"]
    tdz_prefix = module.params["tdz_prefix"]
    test_alert = module.params["test_alert"]
    timezone = module.params["timezone"]
    tlsv1_enabled = module.params["tlsv1_enabled"]
    user_inactivity_timeout = module.params["user_inactivity_timeout"]
    validate_merge = module.params["validate_merge"]
    vss_validation_timeout = module.params["vss_validation_timeout"]
    vvol_enabled = module.params["vvol_enabled"]

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
        if state == "present":
            if reboot is True:
                return_status, changed, msg, changed_attrs_dict = reboot_group(client_obj, group_name)

            elif halt is True:
                return_status, changed, msg, changed_attrs_dict = halt_group(client_obj, group_name, force=force)

            elif test_alert is True:
                return_status, changed, msg, changed_attrs_dict = test_alert_group(client_obj, group_name, level)

            elif validate_merge is True:
                return_status, changed, msg, changed_attrs_dict, resp = validate_merge_group(
                    client_obj,
                    group_name,
                    src_group_ip=src_group_ip,
                    src_group_name=src_group_name,
                    src_password=src_password,
                    src_username=src_username,
                    skip_secondary_mgmt_ip=skip_secondary_mgmt_ip,
                    src_passphrase=src_passphrase)

            elif merge is True:
                return_status, changed, msg, changed_attrs_dict, resp = merge_group(
                    client_obj,
                    group_name,
                    src_group_ip=src_group_ip,
                    src_group_name=src_group_name,
                    src_password=src_password,
                    src_username=src_username,
                    force=force,
                    skip_secondary_mgmt_ip=skip_secondary_mgmt_ip,
                    src_passphrase=src_passphrase)

            elif check_migrate is True:
                return_status, changed, msg, changed_attrs_dict = check_migrate_group(client_obj, group_name)

            elif migrate is True:
                return_status, changed, msg, changed_attrs_dict = migrate_group(client_obj, group_name)

            else:
                # update op
                return_status, changed, msg, changed_attrs_dict, resp = update_group(
                    client_obj,
                    group_name,
                    name=change_name,
                    alarms=alarms,
                    alert_to_email_addrs=alert_to_email_addrs,
                    alert_from_email_addrs=alert_from_email_addrs,
                    alert_min_level=alert_min_level,
                    allow_analytics_gui=allow_analytics_gui,
                    allow_support_tunnel=allow_support_tunnel,
                    auto_switchover=auto_switchover,
                    autoclean_unmanaged_snapshots=autoclean_unmanaged_snapshots,
                    autoclean_unmanaged_snapshots_ttl_unit=autoclean_unmanaged_snapshots_ttl_unit,
                    autosupport=autosupport,
                    cc_mode=cc_mode,
                    date=date,
                    default_iscsi_target_scope=default_iscsi_target_scope,
                    default_volume_limit=default_volume_limit,
                    domain_name=domain_name,
                    dns_servers=dns_servers,
                    fc_enabled=fc_enabled,
                    group_snapshot_ttl=group_snapshot_ttl,
                    group_target_enabled=group_target_enabled,
                    group_target_name=group_target_name,
                    iscsi_enabled=iscsi_enabled,
                    isns_enabled=isns_enabled,
                    isns_port=isns_port,
                    isns_server=isns_server,
                    login_banner_after_auth=login_banner_after_auth,
                    login_banner_message=login_banner_message,
                    login_banner_reset=login_banner_reset,
                    ntp_server=ntp_server,
                    proxy_port=proxy_port,
                    proxy_password=proxy_password,
                    proxy_server=proxy_server,
                    proxy_username=proxy_username,
                    repl_throttle_list=repl_throttle_list,
                    send_alert_to_support=send_alert_to_support,
                    smtp_auth_enabled=smtp_auth_enabled,
                    smtp_auth_password=smtp_auth_password,
                    smtp_auth_username=smtp_auth_username,
                    smtp_port=smtp_port,
                    smtp_encrypt_type=smtp_encrypt_type,
                    snmp_community=snmp_community,
                    snmp_get_enabled=snmp_get_enabled,
                    snmp_get_port=snmp_get_port,
                    snmp_trap_enabled=snmp_trap_enabled,
                    snmp_trap_host=snmp_trap_host,
                    snmp_trap_port=snmp_trap_port,
                    snmp_sys_contact=snmp_sys_contact,
                    snmp_sys_location=snmp_sys_location,
                    syslogd_enabled=syslogd_enabled,
                    syslogd_port=syslogd_port,
                    syslogd_server=syslogd_server,
                    tdz_enabled=tdz_enabled,
                    tdz_prefix=tdz_prefix,
                    timezone=timezone,
                    tlsv1_enabled=tlsv1_enabled,
                    user_inactivity_timeout=user_inactivity_timeout,
                    vss_validation_timeout=vss_validation_timeout,
                    vvol_enabled=vvol_enabled)

        elif state == "absent":
            return_status, changed, msg, changed_attrs_dict = reboot_group(client_obj, group_name)
    except Exception as ex:
        # failed for some reason.
        msg = str(ex)

    if return_status:
        if utils.is_null_or_empty(resp):
            module.exit_json(return_status=return_status, changed=changed, msg=msg)
        else:
            module.exit_json(return_status=return_status, changed=changed, msg=msg, attrs=resp)
    else:
        if utils.is_null_or_empty(resp):
            module.fail_json(return_status=return_status, changed=changed, msg=msg)
        else:
            module.fail_json(return_status=return_status, changed=changed, msg=msg, attrs=resp)


if __name__ == '__main__':
    main()

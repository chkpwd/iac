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
description:
  - Collect information from a HPE Nimble Storage array. By default, the module will collect basic information
    including array, groups config, protection templates, protection schedules, snapshots, snapshot collections, volume
    collections and volume counts. Additional information can be collected based on the configured set of arguments.
module: hpe_nimble_info
options:
  gather_subset:
    required: False
    default: minimum
    type: list
    elements: raw
    description:
      - When supplied, this argument will define the information to be collected. Possible values for this include "all" "minimum" "config"
        "access_control_records", "alarms", "application_servers", "application_categories", "arrays", "chap_users", "controllers", "disks",
        "fibre_channel_interfaces", "fibre_channel_configs", "fibre_channel_initiator_aliases", "fibre_channel_ports", "folders", "groups",
        "initiator_groups", "initiators", "master_key", "network_configs", "performance_policies", "pools", "protection_schedules",
        "protection_templates", "protocol_endpoints", "replication_partners", "shelves", "snapshots", "snapshot_collections", "software_versions",
        "user_groups", "user_policies", "users", "volumes", "volume_collections".

      - Each subset except "all", "minimum" and "config" supports four types of subset options. Subset "all" supports limit and detail as subset options.
        Subset "config" and "minimum" does not support any subset options.

      - See the example section for usage of the following subset options.
      - fields - A string representing which attributes to display for a given subset.
      - limit - An integer value which represents how many latest items to show for a given subset.
      - detail - A bool flag when set to true fetches everything for a given subset. Default is "True".
      - query - A key-value pair to query.
extends_documentation_fragment: hpe.nimble.hpe_nimble
short_description: Collect information from HPE Nimble Storage array
version_added: "1.0.0"
notes:
  - This module supports C(check_mode).
'''

EXAMPLES = r'''

- name: Collect default set of information
  hpe.nimble.hpe_nimble_info:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    gather_subset:
      - minimum:
  register: array_info

- name: Show default information
  ansible.builtin.debug:
    msg: "{{ array_info['nimble_info']['default'] }}"

- name: Collect config
  hpe.nimble.hpe_nimble_info:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    gather_subset:
      - config:
  register: array_info

- name: Show config information
  ansible.builtin.debug:
    msg: "{{ array_info['nimble_info']['config'] }}"

- name: Collect all
  hpe.nimble.hpe_nimble_info:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    gather_subset:
      - all:
          limit: 1
  register: array_info

- name: Show all information
  ansible.builtin.debug:
    msg: "{{ array_info['nimble_info'] }}"

- name: Collect volume, snapshot and volume collection. Below query will show just one
        snapshot detail with attributes 'name and id' for a volume called 'vol1'
  hpe.nimble.hpe_nimble_info:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    gather_subset:
      - volumes:
          fields: "name,id"
          limit: 2
      - volume_collections:
          limit: 1
          detail: false
      - snapshots:
          fields: "name,id"
          query:
            vol_name: "vol1"
          limit: 1
          detail: True
  register: array_info

- name: Show information
  ansible.builtin.debug:
    msg: "{{ array_info['nimble_info'] }}"

'''
RETURN = r'''
nimble_info:
  description: Returns the information collected from the HPE Nimble Storage array
  returned: always
  type: complex
  contains: {}
  sample: {
    "config": {
        "arrays": [
            {
                "all_flash": false,
                "extended_model": "vmware-4G-5T-160F",
                "full_name": "ansibler1-va",
                "role": "leader",
                "serial": "ansibler1-va"
            }
        ],
        "groups": [
            {
                "alarms_enabled": true,
                "auto_switchover_enabled": true,
                "auto_switchover_messages": [],
                "autosupport_enabled": true,
                "default_iscsi_target_scope": "group",
                "dns_servers": [
                    {
                        "ip_addr": "10.235.0.185"
                    },
                    {
                        "ip_addr": "10.1.255.254"
                    }
                ],
                "domain_name": "vlab.nimblestorage.com",
                "encryption_config": {
                    "cipher": "aes_256_xts",
                    "encryption_active": true,
                    "encryption_key_manager": "local",
                    "master_key_set": true,
                    "mode": "available",
                    "scope": "group"
                },
                "failover_mode": "Manual",
                "fc_enabled": false,
                "iscsi_enabled": true,
                "isns_enabled": true,
                "leader_array_name": "ansibler1-va",
                "member_list": [
                    "ansibler1-va"
                ],
                "name": "group-ansibler1-va",
                "ntp_server": "time.nimblestorage.com",
                "send_alert_to_support": true,
                "smtp_auth_enabled": false,
                "smtp_auth_username": "",
                "smtp_port": 25,
                "smtp_server": "",
                "snmp_community": "public",
                "snmp_trap_enabled": false,
                "snmp_trap_host": "",
                "snmp_trap_port": 162,
                "syslogd_enabled": false,
                "syslogd_server": "",
                "vvol_enabled": true
            }
        ],
        "network_configs": [
            {
                "active_since": 1592210265,
                "array_list": [
                    {
                        "ctrlr_a_support_ip": "10.18.1.1",
                        "ctrlr_b_support_ip": "10.18.2.2",
                        "member_gid": 1,
                        "name": "ansibler1-va",
                        "nic_list": [
                            {
                                "data_ip": "172.16.41.139",
                                "name": "eth3",
                                "subnet_label": "data1",
                                "tagged": false
                            },
                            {
                                "data_ip": "172.16.234.76",
                                "name": "eth4",
                                "subnet_label": "data2",
                                "tagged": false
                            },
                            {
                                "data_ip": "",
                                "name": "eth2",
                                "subnet_label": "mgmt-data",
                                "tagged": false
                            },
                            {
                                "data_ip": "",
                                "name": "eth1",
                                "subnet_label": "mgmt-data",
                                "tagged": false
                            }
                        ]
                    }
                ],
                "creation_time": 1586411318,
                "group_leader_array": "ansibler1-va",
                "id": "177321e77f009f2013000000000000000000000001",
                "iscsi_automatic_connection_method": true,
                "iscsi_connection_rebalancing": true,
                "last_active": 1592210256,
                "last_modified": 1586411356,
                "mgmt_ip": "10.18.171.96",
                "name": "active",
                "role": "active",
                "route_list": [
                    {
                        "gateway": "10.18.160.1",
                        "tgt_netmask": "0.0.0.0",
                        "tgt_network": "0.0.0.0"
                    }
                ],
                "secondary_mgmt_ip": "",
                "subnet_list": [
                    {
                        "allow_group": true,
                        "allow_iscsi": true,
                        "discovery_ip": "172.16.41.140",
                        "failover": true,
                        "failover_enable_time": 0,
                        "label": "data1",
                        "mtu": 1500,
                        "netmask": "255.255.224.0",
                        "network": "172.16.32.0",
                        "netzone_type": "single",
                        "type": "data",
                        "vlan_id": 0
                    },
                    {
                        "allow_group": true,
                        "allow_iscsi": true,
                        "discovery_ip": "172.16.234.101",
                        "failover": true,
                        "failover_enable_time": 0,
                        "label": "data2",
                        "mtu": 1500,
                        "netmask": "255.255.224.0",
                        "network": "172.16.224.0",
                        "netzone_type": "single",
                        "type": "data",
                        "vlan_id": 0
                    },
                    {
                        "allow_group": false,
                        "allow_iscsi": false,
                        "discovery_ip": "",
                        "failover": true,
                        "failover_enable_time": 0,
                        "label": "mgmt-data",
                        "mtu": 1500,
                        "netmask": "255.255.224.0",
                        "network": "10.18.160.0",
                        "netzone_type": "none",
                        "type": "mgmt",
                        "vlan_id": 0
                    }
                ]
            },
            {
                "active_since": 0,
                "array_list": [
                    {
                        "ctrlr_a_support_ip": "10.18.1.1",
                        "ctrlr_b_support_ip": "10.18.2.2",
                        "member_gid": 1,
                        "name": "ansibler1-va",
                        "nic_list": [
                            {
                                "data_ip": "",
                                "name": "eth2",
                                "subnet_label": "mgmt-data",
                                "tagged": false
                            },
                            {
                                "data_ip": "",
                                "name": "eth1",
                                "subnet_label": "mgmt-data",
                                "tagged": false
                            },
                            {
                                "data_ip": "172.16.41.139",
                                "name": "eth3",
                                "subnet_label": "data1",
                                "tagged": false
                            },
                            {
                                "data_ip": "172.16.234.76",
                                "name": "eth4",
                                "subnet_label": "data2",
                                "tagged": false
                            }
                        ]
                    }
                ],
                "creation_time": 1586411356,
                "group_leader_array": "ansibler1-va",
                "id": "177321e77f009f2013000000000000000000000002",
                "iscsi_automatic_connection_method": true,
                "iscsi_connection_rebalancing": true,
                "last_active": 1592210265,
                "last_modified": 1586411318,
                "mgmt_ip": "10.18.171.96",
                "name": "backup",
                "role": "backup",
                "route_list": [
                    {
                        "gateway": "10.18.160.1",
                        "tgt_netmask": "0.0.0.0",
                        "tgt_network": "0.0.0.0"
                    }
                ],
                "secondary_mgmt_ip": "",
                "subnet_list": [
                    {
                        "allow_group": false,
                        "allow_iscsi": false,
                        "discovery_ip": "",
                        "failover": true,
                        "failover_enable_time": 0,
                        "label": "mgmt-data",
                        "mtu": 1500,
                        "netmask": "255.255.224.0",
                        "network": "10.18.160.0",
                        "netzone_type": "none",
                        "type": "mgmt",
                        "vlan_id": 0
                    },
                    {
                        "allow_group": true,
                        "allow_iscsi": true,
                        "discovery_ip": "172.16.41.140",
                        "failover": true,
                        "failover_enable_time": 0,
                        "label": "data1",
                        "mtu": 1500,
                        "netmask": "255.255.224.0",
                        "network": "172.16.32.0",
                        "netzone_type": "single",
                        "type": "data",
                        "vlan_id": 0
                    },
                    {
                        "allow_group": true,
                        "allow_iscsi": true,
                        "discovery_ip": "172.16.234.101",
                        "failover": true,
                        "failover_enable_time": 0,
                        "label": "data2",
                        "mtu": 1500,
                        "netmask": "255.255.224.0",
                        "network": "172.16.224.0",
                        "netzone_type": "single",
                        "type": "data",
                        "vlan_id": 0
                    }
                ]
            }
        ],
        "pools": [
            {
                "array_count": 1,
                "dedupe_all_volumes": false,
                "dedupe_capable": false,
                "is_default": true,
                "name": "default",
                "vol_list": [
                    {
                        "id": "0675a5e21cc205c609000000000000000000000001",
                        "name": "vol1",
                        "vol_id": "0675a5e21cc205c609000000000000000000000001",
                        "vol_name": "vol1"
                    },
                    {
                        "id": "067321e77f009f2013000000000000000000000271",
                        "name": "volumetc-vol1-0-24-07-2020-71470d6d-cd6e-11ea-9165-00505696c568",
                        "vol_id": "067321e77f009f2013000000000000000000000271",
                        "vol_name": "volumetc-vol1-0-24-07-2020-71470d6d-cd6e-11ea-9165-00505696c568"
                    },
                    {
                        "id": "067321e77f009f201300000000000000000000024d",
                        "name": "ansible-vol1",
                        "vol_id": "067321e77f009f201300000000000000000000024d",
                        "vol_name": "ansible-vol1"
                    }
                ]
            }
        ]
    },
    "default": {
                    "arrays": [
                        {
                            "all_flash": false,
                            "extended_model": "vmware-4G-5T-160F",
                            "full_name": "ansibler1-va"
                        }
                    ],
                    "disks": 16,
                    "folders": 0,
                    "groups": [
                        {
                            "auto_switchover_messages": [],
                            "default_iscsi_target_scope": "group",
                            "encryption_config": {
                                "cipher": "aes_256_xts",
                                "encryption_active": true,
                                "encryption_key_manager": "local",
                                "master_key_set": true,
                                "mode": "available",
                                "scope": "group"
                            },
                            "fc_enabled": false,
                            "iscsi_enabled": true,
                            "leader_array_name": "ansibler1-va",
                            "name": "group-ansibler1-va",
                            "num_snaps": 49
                        }
                    ],
                    "initiator_groups": 1,
                    "protection_schedules": 6,
                    "protection_templates": 3,
                    "protocol_endpoints": 0,
                    "snapshot_collections": 49,
                    "snapshots": 49,
                    "software_versions": "5.2.2.0-730069-opt",
                    "users": 2,
                    "volume_collections": 1,
                    "volumes": 3
    },
    "snapshots":
    [
        {
          "access_control_records": null,
          "agent_type": "none",
          "app_uuid": "",
          "creation_time": 1586429663,
          "description": "Replicated by protection policy volcoll2 schedule Schedule-new",
          "expiry_after": 1,
          "expiry_time": 0,
          "id": "0475a5e21cc205c609000000000000000200000004",
          "is_manually_managed": true,
          "is_replica": true,
          "is_unmanaged": false,
          "last_modified": 1586429956,
          "metadata": null,
          "name": "adfsasfasfasf",
          "new_data_compressed_bytes": 0,
          "new_data_uncompressed_bytes": 0,
          "new_data_valid": true,
          "offline_reason": "user",
          "online": false,
          "origin_name": "",
          "pool_name": "default",
          "replication_status": null,
          "schedule_id": "0c7321e77f009f2013000000000000000000000008",
          "schedule_name": "Schedule-new",
          "serial_number": "022e0240e677ef2f6c9ce9006cc7be73",
          "size": 1073741824,
          "snap_collection_id": "0575a5e21cc205c609000000000000000000000004",
          "snap_collection_name": "adfsasfasfasf",
          "target_name": "iqn.2007-11.com.nimblestorage:group-ansibler1-va-g7321e77f009f2013",
          "vol_id": "0675a5e21cc205c609000000000000000000000001",
          "vol_name": "vol1",
          "vpd_ieee0": "022e0240e677ef2f",
          "vpd_ieee1": "6c9ce9006cc7be73",
          "vpd_t10": "Nimble  022e0240e677ef2f6c9ce9006cc7be73",
          "writable": false
        }
    ],
    "volume_collections":
    [
      "volcoll2": {
          "id": "077321e77f009f2013000000000000000000000005",
          "name": "volcoll2"
      }
    ],
    "volumes":
    [
      "10.18.180.239-ansible-vol1": {
          "id": "067321e77f009f2013000000000000000000000230",
          "name": "10.18.180.239-ansible-vol1"
      },
      "changed-volname": {
          "id": "067321e77f009f201300000000000000000000022f",
          "name": "changed-volname"
      }
    ]
  }
'''

from ansible.module_utils.basic import AnsibleModule
try:
    from nimbleclient.v1 import client
except ImportError:
    client = None
from ansible_collections.hpe.nimble.plugins.module_utils.hpe_nimble import __version__ as NIMBLE_ANSIBLE_VERSION
import ansible_collections.hpe.nimble.plugins.module_utils.hpe_nimble as utils
import re

limit_not_supported = [
    "controllers",
    "disks",
    "shelves",
    "software_versions"
]


def add_to_valid_subset_list(valid_subset_list,
                             subset_name,
                             subset_options,
                             fetch_all=False):

    if valid_subset_list is None:
        return []
    valid_subset = {}
    fields = query = limit = None
    detail = True  # default
    count = -1

    if subset_options is not None:
        if 'fields' in subset_options and subset_options['fields'] is not None:
            temp = ""
            for item in subset_options['fields']:
                temp += item + ','
            fields = temp.strip(',')
            # fields = subset_options['fields'].strip()
        if 'detail' in subset_options and subset_options['detail'] is not None:
            detail = subset_options['detail']
        if 'limit' in subset_options:
            count = limit = subset_options['limit']
            if fetch_all is True:
                # few subset do not support limit option. hence in case of subset 'all' ,set it to none
                if subset_name in limit_not_supported:
                    limit = None

    if subset_options is not None and 'query' in subset_options:
        query = subset_options['query']

    valid_subset['name'] = subset_name.lower()
    valid_subset['fields'] = fields
    valid_subset['query'] = query
    valid_subset['limit'] = limit
    valid_subset['detail'] = detail
    valid_subset['count'] = count
    valid_subset_list.append(dict(valid_subset))
    return valid_subset_list


def is_subset_option_valid(subset_options):
    if subset_options is None:
        return (True, "", "")
    if isinstance(subset_options, dict) is False:
        raise Exception("Subset options should be provided as dictionary.")
    for key, value in subset_options.items():
        if key != "fields" and key != "query" and key != "limit" and key != "detail":
            return (False, key, "Valid subset option names are:'fields', 'query', 'limit', and 'detail'")
        if key == 'limit' and type(value) is not int:
            return (False, key, "Subset options 'limit' should be provided as integer.")
        if key == 'detail' and type(value) is not bool:
            return (False, key, "Subset options 'detail' should be provided as bool.")
        if key == 'fields' and type(value) is not list:
            return (False, key, "Subset options 'fields' should be provided as list.")
        if key == 'query' and type(value) is not dict:
            return (False, key, "Subset options 'query' should be provided as dict.")
    return (True, "", "")


def is_subset_already_added(key, valid_subset_list):
    if valid_subset_list is None:
        return False
    for item in valid_subset_list:
        if key == item['name']:
            return True
    return False


def handle_all_subset(info_subset, valid_subset_list, subset_options):

    if valid_subset_list is None or info_subset is None:
        return []
    msg = "Subset options 'fields and query' cannot be used with 'all' subset. Only 'limit and detail' option can be used."

    if subset_options is not None:
        if 'fields' in subset_options or 'query' in subset_options:
            raise Exception(msg)

    for key, value in info_subset.items():
        if (is_subset_already_added(key, valid_subset_list) is False
                and (key != 'minimum' and key != 'config' and key != 'snapshots')):
            add_to_valid_subset_list(valid_subset_list, key, subset_options, True)
    return valid_subset_list


def raise_invalid_subset_ex(key):
    msg = f"Subset name '{key}' is not valid. Please provide a correct subset name."
    raise Exception(msg)


def raise_repeat_subset_ex(key):
    msg = f"Subset '{key}' is already provided as input. Please remove one entry."
    raise Exception(msg)


def raise_subset_mutually_exclusive_ex():
    msg = "Subset 'all' and 'minimum' are mutually exclusive. Please provide only one of them"
    raise Exception(msg)


def parse_subset_list(info_subset, gather_subset):
    valid_subset_list = []
    try:
        if gather_subset is None or isinstance(gather_subset, list) is False:
            add_to_valid_subset_list(valid_subset_list, 'minimum', None)
            return valid_subset_list
        # each entry in gather subset represents a dictonary or list for each object set
        for object_set in gather_subset:
            object_set_type = type(object_set)

            if object_set_type is dict:
                for key, subset_options in object_set.items():
                    key = key.strip()
                    if info_subset.get(key, None) is None:
                        raise_invalid_subset_ex(key)
                    flag, param_key, err_msg = is_subset_option_valid(subset_options)

                    if flag is False:
                        msg = f"Invalid subset option '{param_key}' provided for subset '{key}'."
                        raise Exception(msg + ' ' + err_msg)
                    else:
                        if key == 'all':
                            if is_subset_already_added('minimum', valid_subset_list) is True:
                                raise_subset_mutually_exclusive_ex()
                            handle_all_subset(info_subset, valid_subset_list, subset_options)
                            continue
                        if key == 'minimum' or key == 'config':
                            if subset_options is not None:
                                raise Exception("Subset options cannot be used with 'minimum' and 'config' subset.")
                            if key == 'minimum':
                                if is_subset_already_added('all', valid_subset_list) is True:
                                    raise_subset_mutually_exclusive_ex()
                        elif is_subset_already_added(key, valid_subset_list) is True:
                            raise_repeat_subset_ex(key)
                        add_to_valid_subset_list(valid_subset_list, key, subset_options)
            elif object_set_type is str:
                key = object_set.strip()
                if info_subset.get(key, None) is None:
                    raise_invalid_subset_ex(key)

                if is_subset_already_added(key, valid_subset_list) is True:
                    raise_repeat_subset_ex(key)

                if key == 'all':
                    if is_subset_already_added('minimum', valid_subset_list) is True:
                        raise_subset_mutually_exclusive_ex()
                    handle_all_subset(info_subset, valid_subset_list, None)
                    continue

                add_to_valid_subset_list(valid_subset_list, key, None)
        return (valid_subset_list)
    except Exception as ex:
        raise(ex)


def generate_dict(name, resp):
    temp_dict = {}
    if utils.is_null_or_empty(resp) or name is None:
        return {}
    for item in resp:
        key = item.attrs.get(name)
        if key in temp_dict:
            # we need to convert the dict into a list of items as we have more than one item for the same key
            temp_list = [temp_dict[key]]
            if isinstance(temp_dict[key], dict) is True:
                temp_dict.pop(key)
            temp_dict.setdefault(key, temp_list).append(item.attrs)
        elif key is None or key == "N/A":
            temp_dict.setdefault(name, []).append(item.attrs)
        else:
            temp_dict[key] = item.attrs
    return temp_dict


def fetch_config_subset(info_subset):
    if info_subset is None:
        return ({}, True)
    toreturn = {'config': {}}
    result = {}
    temp_dict = {}
    grp_fields = """
        smtp_server,
        smtp_port,
        smtp_auth_enabled,
        smtp_auth_username,
        autosupport_enabled,
        send_alert_to_support,
        isns_enabled,
        snmp_trap_enabled,
        snmp_trap_host,
        snmp_trap_port,
        snmp_community,
        domain_name,
        dns_servers,
        ntp_server,
        syslogd_enabled,
        syslogd_server,
        vvol_enabled,
        alarms_enabled,
        member_list,
        encryption_config,
        name,
        fc_enabled,
        iscsi_enabled

    """
    try:
        for key, cl_obj in info_subset.items():
            if key == 'arrays':
                resp = cl_obj.list(detail=True, fields="extended_model,full_name,all_flash,serial,role")
            elif key == 'groups':
                resp = cl_obj.list(detail=True, fields=re.sub('\\s+', '', grp_fields))
            elif key == 'pools':
                resp = cl_obj.list(detail=True, fields="array_count,dedupe_all_volumes,dedupe_capable,is_default,name,vol_list")
            elif key == 'network_configs':
                resp = cl_obj.list(detail=True)
            else:
                continue
            temp_dict[key] = resp
        # prepare
        result['arrays'] = generate_dict('arrays', temp_dict['arrays'])['arrays']
        result['groups'] = generate_dict('groups', temp_dict['groups'])['groups']
        result['pools'] = generate_dict('pools', temp_dict['pools'])['pools']
        result['network_configs'] = generate_dict('network_configs', temp_dict['network_configs'])['network_configs']
        toreturn['config'] = result
        return (toreturn, True)
    except Exception:
        raise


def fetch_minimum_subset(info_subset):

    if info_subset is None:
        return ({}, True)
    minimum_subset = [
        "arrays",
        "disks",
        "folders",
        "groups",
        "initiator_groups",
        "performance_policies",
        "pools",
        "protection_schedules",
        "protection_templates",
        "protocol_endpoints",
        "snapshot_collections",
        "software_versions",
        "users",
        "volumes",
        "volume_collections"
    ]
    toreturn = {'default': {}}
    result = {}
    temp_dict = {}

    try:
        for key in minimum_subset:
            cl_obj = info_subset[key]
            if key == 'arrays':
                resp = cl_obj.list(detail=True, fields="extended_model,full_name,all_flash")
            elif key == 'groups':
                # certain fields were only added in NimOS 5.1 and above
                if utils.is_array_version_above_or_equal(info_subset['arrays'], "5.1"):
                    resp = cl_obj.list(detail=True,
                                       fields="encryption_config,name,fc_enabled,iscsi_enabled,leader_array_name,default_iscsi_target_scope,num_snaps")
                else:
                    resp = cl_obj.list(detail=True, fields="name")
            else:
                resp = cl_obj.list(detail=False)
            temp_dict[key] = resp
        # prepare
        result['volumes'] = len(temp_dict['volumes'])
        result['volume_collections'] = len(temp_dict['volume_collections'])
        result['users'] = len(temp_dict['users'])
        result['software_versions'] = temp_dict['software_versions'][-1].attrs.get('version')  # get the latest
        result['snapshot_collections'] = len(temp_dict['snapshot_collections'])
        result['snapshots'] = temp_dict['groups'][-1].attrs.get('num_snaps')
        result['protocol_endpoints'] = len(temp_dict['protocol_endpoints'])
        result['protection_templates'] = len(temp_dict['protection_templates'])
        result['protection_schedules'] = len(temp_dict['protection_schedules'])
        result['initiator_groups'] = len(temp_dict['initiator_groups'])
        result['folders'] = len(temp_dict['folders'])
        result['disks'] = len(temp_dict['disks'])
        result['folders'] = len(temp_dict['folders'])
        result['arrays'] = generate_dict('arrays', temp_dict['arrays'])['arrays']
        result['groups'] = generate_dict('groups', temp_dict['groups'])['groups']
        toreturn['default'] = result
        return (toreturn, True)
    except Exception as ex:
        result['failed'] = str(ex)
        toreturn['default'] = result
        return (toreturn, False)

# snapshots actually needs a vol_name/vol_id as mandatory params. Hence ,in case of 'all' subset
# where user cannot provide a query option. we need to fetch the snapshots by iterating
# over the list of volumes and see if those volumes have snapshots.


def fetch_snapshots_for_all_subset(subset, client_obj):
    if subset is None or client_obj is None:
        return {}
    result = {}
    total_snap = []
    # get the volume list
    vol_list_resp = client_obj.volumes.list(detail=False)
    if vol_list_resp is not None and vol_list_resp.__len__() > 0:
        for vol_item in vol_list_resp:
            vol_name = vol_item.attrs.get('name')
            snap_list = client_obj.snapshots.list(detail=subset['detail'], vol_name=vol_name, limit=subset['limit'])
            if snap_list is not None and snap_list.__len__() > 0:
                total_snap.extend(snap_list)
                if subset['limit'] is not None and total_snap.__len__() >= subset['limit']:
                    total_snap = total_snap[0:subset['limit']]
                    break
        if total_snap.__len__() > 0:
            result['snapshots'] = generate_dict('snapshots', total_snap)['snapshots']
    return result


def fetch_subset(valid_subset_list, info_subset):
    if valid_subset_list is None or isinstance(valid_subset_list, list) is False:
        return {}
    try:
        result_dict = {}
        resp = None
        for subset in valid_subset_list:
            result = {}
            try:
                if subset['name'] == "minimum":
                    result, flag = fetch_minimum_subset(info_subset)
                    if flag is False:
                        raise Exception(result)
                elif subset['name'] == "config":
                    result, flag = fetch_config_subset(info_subset)
                    if flag is False:
                        raise Exception(result)
                elif subset['name'] == "all":
                    result = fetch_snapshots_for_all_subset(subset, info_subset['all'])
                    for key, value in result.items():
                        result_dict[key] = value
                    continue
                else:
                    # if subset is user_policies then make sure nimos aversion is fiji and above
                    if subset['name'] == 'user_policies' and utils.is_array_version_above_or_equal(info_subset['arrays'], "5.1.0") is False:
                        continue
                    cl_obj_set = info_subset[subset['name']]
                    query = subset['query']
                    if query is not None:
                        resp = cl_obj_set.list(detail=subset['detail'], **query, fields=subset['fields'], limit=subset['limit'])
                    else:
                        resp = cl_obj_set.list(detail=subset['detail'], fields=subset['fields'], limit=subset['limit'])
                    if resp is not None and resp.__len__() != 0:
                        # limit is not supported for few subset, hence for those slice the result and keep the number as asked by user.
                        if subset['count'] != -1 and resp.__len__() > subset['count']:
                            resp = resp[: subset['count']]

                        result[subset['name']] = generate_dict('data', resp)['data']
                    else:
                        result[subset['name']] = resp
                for key, value in result.items():
                    result_dict[key] = value
            except Exception as ex:
                msg = f"Failed to fetch {subset['name']} details. Error:'{str(ex)}'"
                raise Exception(msg) from ex
        return result_dict
    except Exception:
        raise


def intialize_info_subset(client_obj):

    info_subset = {
        "all": client_obj,
        "minimum": client_obj,
        "config": client_obj,
        "access_control_records": client_obj.access_control_records,
        "alarms": client_obj.alarms,
        "application_servers": client_obj.application_servers,
        "application_categories": client_obj.application_categories,
        "arrays": client_obj.arrays,
        "chap_users": client_obj.chap_users,
        "controllers": client_obj.controllers,
        "disks": client_obj.disks,
        "fibre_channel_interfaces": client_obj.fibre_channel_interfaces,
        "fibre_channel_configs": client_obj.fibre_channel_configs,
        "fibre_channel_initiator_aliases": client_obj.fibre_channel_initiator_aliases,
        "fibre_channel_ports": client_obj.fibre_channel_ports,
        "folders": client_obj.folders,
        "groups": client_obj.groups,
        "initiator_groups": client_obj.initiator_groups,
        "initiators": client_obj.initiators,
        "master_key": client_obj.master_key,
        "network_configs": client_obj.network_configs,
        "network_interfaces": client_obj.network_interfaces,
        "performance_policies": client_obj.performance_policies,
        "pools": client_obj.pools,
        "protection_schedules": client_obj.protection_schedules,
        "protection_templates": client_obj.protection_templates,
        "protocol_endpoints": client_obj.protocol_endpoints,
        "replication_partners": client_obj.replication_partners,
        "shelves": client_obj.shelves,
        "snapshots": client_obj.snapshots,
        "snapshot_collections": client_obj.snapshot_collections,
        "software_versions": client_obj.software_versions,
        "user_groups": client_obj.user_groups,
        "user_policies": client_obj.user_policies,
        "users": client_obj.users,
        "volumes": client_obj.volumes,
        "volume_collections": client_obj.volume_collections
    }
    return info_subset


def get_subset_info(
        client_obj,
        gather_subset):

    if utils.is_null_or_empty(gather_subset):
        return (False, False, "Please provide atleast one subset.", {})
    result_dict = []
    try:
        info_subset = intialize_info_subset(client_obj)
        valid_subset_list = parse_subset_list(info_subset, gather_subset)
        if valid_subset_list is not None and valid_subset_list.__len__() > 0:
            # we got subset list to work on. get the details of these subset
            result_dict = fetch_subset(valid_subset_list, info_subset)
            return (True, False, "Fetched the subset details.", result_dict)
        else:
            return (True, False, "No vaild subset provided.", result_dict)
    except Exception as ex:
        return (False, False, f"{ex}", {})


def main():

    fields = {
        "gather_subset": {
            "required": False,
            "type": "list",
            "elements": 'raw',
            'default': "minimum"
        }
    }
    default_fields = utils.basic_auth_arg_fields()
    fields.update(default_fields)
    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)
    if client is None:
        module.fail_json(msg='Python nimble-sdk could not be found.')

    hostname = module.params["host"]
    username = module.params["username"]
    password = module.params["password"]
    gather_subset = module.params["gather_subset"]

    if (username is None or password is None or hostname is None):
        module.fail_json(
            msg="Missing variables: hostname, username and password is mandatory.")
    # defaults
    return_status = changed = False
    msg = "No task to run."
    try:
        client_obj = client.NimOSClient(
            hostname,
            username,
            password,
            f"HPE Nimble Ansible Modules v{NIMBLE_ANSIBLE_VERSION}"
        )

        return_status, changed, msg, result_dict = get_subset_info(client_obj, gather_subset)
    except Exception as ex:
        # failed for some reason.
        msg = str(ex)

    if return_status:
        if utils.is_null_or_empty(result_dict) is False and result_dict.__len__() > 0:
            module.exit_json(return_status=return_status,
                             changed=changed,
                             message=msg,
                             nimble_info=result_dict)
        else:
            module.exit_json(return_status=return_status, changed=changed, msg=msg)
    else:
        module.fail_json(return_status=return_status, changed=changed, msg=msg)


if __name__ == '__main__':
    main()

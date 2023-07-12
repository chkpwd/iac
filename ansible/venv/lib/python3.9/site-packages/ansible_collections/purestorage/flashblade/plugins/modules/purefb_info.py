#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2019, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: purefb_info
version_added: '1.0.0'
short_description: Collect information from Pure Storage FlashBlade
description:
  - Collect information from a Pure Storage FlashBlade running the
    Purity//FB operating system. By default, the module will collect basic
    information including hosts, host groups, protection
    groups and volume counts. Additional information can be collected
    based on the configured set of arguements.
author:
  - Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  gather_subset:
    description:
      - When supplied, this argument will define the information to be collected.
        Possible values for this include all, minimum, config, performance,
        capacity, network, subnets, lags, filesystems, snapshots, buckets,
        replication, policies, arrays, accounts, admins, ad, kerberos
        and drives.
    required: false
    type: list
    elements: str
    default: minimum
extends_documentation_fragment:
  - purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: collect default set of info
  purestorage.flashblade.purefb_info:
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
  register: blade_info
- name: show default information
  debug:
    msg: "{{ blade_info['purefb_info']['default'] }}"

- name: collect configuration and capacity info
  purestorage.flashblade.purefb_info:
    gather_subset:
      - config
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
  register: blade_info
- name: show config information
  debug:
    msg: "{{ blade_info['purefb_info']['config'] }}"

- name: collect all info
  purestorage.flashblade.purefb_info:
    gather_subset:
      - all
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
  register: blade_info
- name: show all information
  debug:
    msg: "{{ blade_info['purefb_info'] }}"
"""

RETURN = r"""
purefb_info:
  description: Returns the information collected from the FlashBlade
  returned: always
  type: complex
  sample: {
        "admins": {
            "pureuser": {
                "api_token_timeout": null,
                "local": true,
                "public_key": null
            },
            "another_user": {
                "api_token_timeout": null,
                "local": false,
                "public_key": null
            },
        },
        "buckets": {
            "central": {
                "account_name": "jake",
                "bucket_type": "classic",
                "created": 1628900154000,
                "data_reduction": null,
                "destroyed": false,
                "id": "43758f09-9e71-7bf7-5757-2028a95a2b65",
                "lifecycle_rules": {},
                "object_count": 0,
                "snapshot_space": 0,
                "time_remaining": null,
                "total_physical_space": 0,
                "unique_space": 0,
                "versioning": "none",
                "virtual_space": 0
            },
            "test": {
                "account_name": "acme",
                "bucket_type": "classic",
                "created": 1630591952000,
                "data_reduction": 3.6,
                "destroyed": false,
                "id": "d5f6149c-fbef-f3c5-58b6-8fd143110ba9",
                "lifecycle_rules": {
                    "test": {
                        "abort_incomplete_multipart_uploads_after (days)": 1,
                        "cleanup_expired_object_delete_marker": true,
                        "enabled": true,
                        "keep_current_version_for (days)": null,
                        "keep_current_version_until": "2023-12-21",
                        "keep_previous_version_for (days)": null,
                        "prefix": "foo"
                    }
                },
            },
        },
        "capacity": {
            "aggregate": {
                "data_reduction": 1.1179228,
                "snapshots": 0,
                "total_physical": 17519748439,
                "unique": 17519748439,
                "virtual": 19585726464
            },
            "file-system": {
                "data_reduction": 1.3642412,
                "snapshots": 0,
                "total_physical": 4748219708,
                "unique": 4748219708,
                "virtual": 6477716992
            },
            "object-store": {
                "data_reduction": 1.0263462,
                "snapshots": 0,
                "total_physical": 12771528731,
                "unique": 12771528731,
                "virtual": 6477716992
            },
            "total": 83359896948925
        },
        "config": {
            "alert_watchers": {
                "enabled": true,
                "name": "notify@acmestorage.com"
            },
            "array_management": {
                "base_dn": null,
                "bind_password": null,
                "bind_user": null,
                "enabled": false,
                "name": "management",
                "services": [
                    "management"
                ],
                "uris": []
            },
            "directory_service_roles": {
                "array_admin": {
                    "group": null,
                    "group_base": null
                },
                "ops_admin": {
                    "group": null,
                    "group_base": null
                },
                "readonly": {
                    "group": null,
                    "group_base": null
                },
                "storage_admin": {
                    "group": null,
                    "group_base": null
                }
            },
            "dns": {
                "domain": "demo.acmestorage.com",
                "name": "demo-fb-1",
                "nameservers": [
                    "8.8.8.8"
                ],
                "search": [
                    "demo.acmestorage.com"
                ]
            },
            "nfs_directory_service": {
                "base_dn": null,
                "bind_password": null,
                "bind_user": null,
                "enabled": false,
                "name": "nfs",
                "services": [
                    "nfs"
                ],
                "uris": []
            },
            "ntp": [
                "0.ntp.pool.org"
            ],
            "smb_directory_service": {
                "base_dn": null,
                "bind_password": null,
                "bind_user": null,
                "enabled": false,
                "name": "smb",
                "services": [
                    "smb"
                ],
                "uris": []
            },
            "smtp": {
                "name": "demo-fb-1",
                "relay_host": null,
                "sender_domain": "acmestorage.com"
            },
            "ssl_certs": {
                "certificate": "-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----",
                "common_name": "Acme Storage",
                "country": "US",
                "email": null,
                "intermediate_certificate": null,
                "issued_by": "Acme Storage",
                "issued_to": "Acme Storage",
                "key_size": 4096,
                "locality": null,
                "name": "global",
                "organization": "Acme Storage",
                "organizational_unit": "Acme Storage",
                "passphrase": null,
                "private_key": null,
                "state": null,
                "status": "self-signed",
                "valid_from": "1508433967000",
                "valid_to": "2458833967000"
            }
        },
        "default": {
            "blades": 15,
            "buckets": 7,
            "filesystems": 2,
            "flashblade_name": "demo-fb-1",
            "object_store_accounts": 1,
            "object_store_users": 1,
            "purity_version": "2.2.0",
            "snapshots": 1,
            "total_capacity": 83359896948925,
            "smb_mode": "native"
        },
        "filesystems": {
            "k8s-pvc-d24b1357-579e-11e8-811f-ecf4bbc88f54": {
                "default_group_quota": 0,
                "default_user_quota": 0,
                "destroyed": false,
                "fast_remove": false,
                "hard_limit": true,
                "nfs_rules": "10.21.255.0/24(rw,no_root_squash)",
                "provisioned": 21474836480,
                "snapshot_enabled": false
            },
            "z": {
                "default_group_quota": 0,
                "default_user_quota": 0,
                "destroyed": false,
                "fast_remove": false,
                "hard_limit": false,
                "provisioned": 1073741824,
                "snapshot_enabled": false
            }
        },
        "lag": {
            "uplink": {
                "lag_speed": 0,
                "port_speed": 40000000000,
                "ports": [
                    {
                        "name": "CH1.FM1.ETH1.1"
                    },
                    {
                        "name": "CH1.FM1.ETH1.2"
                    },
                ],
                "status": "healthy"
            }
        },
        "network": {
            "fm1.admin0": {
                "address": "10.10.100.6",
                "gateway": "10.10.100.1",
                "mtu": 1500,
                "netmask": "255.255.255.0",
                "services": [
                    "support"
                ],
                "type": "vip",
                "vlan": 2200
            },
            "fm2.admin0": {
                "address": "10.10.100.7",
                "gateway": "10.10.100.1",
                "mtu": 1500,
                "netmask": "255.255.255.0",
                "services": [
                    "support"
                ],
                "type": "vip",
                "vlan": 2200
            },
            "nfs1": {
                "address": "10.10.100.4",
                "gateway": "10.10.100.1",
                "mtu": 1500,
                "netmask": "255.255.255.0",
                "services": [
                    "data"
                ],
                "type": "vip",
                "vlan": 2200
            },
            "vir0": {
                "address": "10.10.100.5",
                "gateway": "10.10.100.1",
                "mtu": 1500,
                "netmask": "255.255.255.0",
                "services": [
                    "management"
                ],
                "type": "vip",
                "vlan": 2200
            }
        },
        "performance": {
            "aggregate": {
                "bytes_per_op": 0,
                "bytes_per_read": 0,
                "bytes_per_write": 0,
                "read_bytes_per_sec": 0,
                "reads_per_sec": 0,
                "usec_per_other_op": 0,
                "usec_per_read_op": 0,
                "usec_per_write_op": 0,
                "write_bytes_per_sec": 0,
                "writes_per_sec": 0
            },
            "http": {
                "bytes_per_op": 0,
                "bytes_per_read": 0,
                "bytes_per_write": 0,
                "read_bytes_per_sec": 0,
                "reads_per_sec": 0,
                "usec_per_other_op": 0,
                "usec_per_read_op": 0,
                "usec_per_write_op": 0,
                "write_bytes_per_sec": 0,
                "writes_per_sec": 0
            },
            "nfs": {
                "bytes_per_op": 0,
                "bytes_per_read": 0,
                "bytes_per_write": 0,
                "read_bytes_per_sec": 0,
                "reads_per_sec": 0,
                "usec_per_other_op": 0,
                "usec_per_read_op": 0,
                "usec_per_write_op": 0,
                "write_bytes_per_sec": 0,
                "writes_per_sec": 0
            },
            "s3": {
                "bytes_per_op": 0,
                "bytes_per_read": 0,
                "bytes_per_write": 0,
                "read_bytes_per_sec": 0,
                "reads_per_sec": 0,
                "usec_per_other_op": 0,
                "usec_per_read_op": 0,
                "usec_per_write_op": 0,
                "write_bytes_per_sec": 0,
                "writes_per_sec": 0
            }
        },
        "snapshots": {
            "z.188": {
                "destroyed": false,
                "source": "z",
                "source_destroyed": false,
                "suffix": "188"
            }
        },
        "subnet": {
            "new-mgmt": {
                "gateway": "10.10.100.1",
                "interfaces": [
                    {
                        "name": "fm1.admin0"
                    },
                    {
                        "name": "fm2.admin0"
                    },
                    {
                        "name": "nfs1"
                    },
                    {
                        "name": "vir0"
                    }
                ],
                "lag": "uplink",
                "mtu": 1500,
                "prefix": "10.10.100.0/24",
                "services": [
                    "data",
                    "management",
                    "support"
                ],
                "vlan": 2200
            }
        }
    }
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_blade,
    get_system,
    purefb_argument_spec,
)
from datetime import datetime


MIN_REQUIRED_API_VERSION = "1.3"
HARD_LIMIT_API_VERSION = "1.4"
POLICIES_API_VERSION = "1.5"
CERT_GROUPS_API_VERSION = "1.8"
REPLICATION_API_VERSION = "1.9"
MULTIPROTOCOL_API_VERSION = "1.11"
MIN_32_API = "2.0"
LIFECYCLE_API_VERSION = "2.1"
SMB_MODE_API_VERSION = "2.2"
NFS_POLICY_API_VERSION = "2.3"
VSO_VERSION = "2.4"
DRIVES_API_VERSION = "2.5"
SECURITY_API_VERSION = "2.7"
BUCKET_API_VERSION = "2.8"


def _millisecs_to_time(millisecs):
    if millisecs:
        return (str(int(millisecs / 3600000 % 24)).zfill(2) + ":00",)
    return None


def _bytes_to_human(bytes_number):
    if bytes_number:
        labels = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s", "PB/s"]
        i = 0
        double_bytes = bytes_number
        while i < len(labels) and bytes_number >= 1024:
            double_bytes = bytes_number / 1024.0
            i += 1
            bytes_number = bytes_number / 1024
        return str(round(double_bytes, 2)) + " " + labels[i]
    return None


def generate_default_dict(module, blade):
    default_info = {}
    defaults = blade.arrays.list_arrays().items[0]
    default_info["flashblade_name"] = defaults.name
    default_info["purity_version"] = defaults.version
    default_info["filesystems"] = len(blade.file_systems.list_file_systems().items)
    default_info["snapshots"] = len(
        blade.file_system_snapshots.list_file_system_snapshots().items
    )
    default_info["buckets"] = len(blade.buckets.list_buckets().items)
    default_info["object_store_users"] = len(
        blade.object_store_users.list_object_store_users().items
    )
    default_info["object_store_accounts"] = len(
        blade.object_store_accounts.list_object_store_accounts().items
    )
    default_info["blades"] = len(blade.blade.list_blades().items)
    default_info["certificates"] = len(blade.certificates.list_certificates().items)
    default_info["total_capacity"] = blade.arrays.list_arrays_space().items[0].capacity
    api_version = blade.api_version.list_versions().versions
    default_info["api_versions"] = api_version
    if POLICIES_API_VERSION in api_version:
        default_info["policies"] = len(blade.policies.list_policies().items)
    if CERT_GROUPS_API_VERSION in api_version:
        default_info["certificate_groups"] = len(
            blade.certificate_groups.list_certificate_groups().items
        )
    if REPLICATION_API_VERSION in api_version:
        default_info["fs_replicas"] = len(
            blade.file_system_replica_links.list_file_system_replica_links().items
        )
        default_info["remote_credentials"] = len(
            blade.object_store_remote_credentials.list_object_store_remote_credentials().items
        )
        default_info["bucket_replicas"] = len(
            blade.bucket_replica_links.list_bucket_replica_links().items
        )
        default_info["connected_arrays"] = len(
            blade.array_connections.list_array_connections().items
        )
        default_info["targets"] = len(blade.targets.list_targets().items)
        default_info["kerberos_keytabs"] = len(blade.keytabs.list_keytabs().items)
    # This section is just for REST 2.x features
    if MIN_32_API in api_version:
        blade = get_system(module)
        blade_info = list(blade.get_arrays().items)[0]
        default_info["object_store_virtual_hosts"] = len(
            blade.get_object_store_virtual_hosts().items
        )
        default_info["api_clients"] = len(blade.get_api_clients().items)
        default_info["idle_timeout"] = int(blade_info.idle_timeout / 60000)
        if list(blade.get_arrays_eula().items)[0].signature.accepted:
            default_info["EULA"] = "Signed"
        else:
            default_info["EULA"] = "Not Signed"
        if NFS_POLICY_API_VERSION in api_version:
            admin_settings = list(blade.get_admins_settings().items)[0]
            default_info["max_login_attempts"] = admin_settings.max_login_attempts
            default_info["min_password_length"] = admin_settings.min_password_length
            if admin_settings.lockout_duration:
                default_info["lockout_duration"] = (
                    str(admin_settings.lockout_duration / 1000) + " seconds"
                )
        if NFS_POLICY_API_VERSION in api_version:
            default_info["smb_mode"] = blade_info.smb_mode
        if VSO_VERSION in api_version:
            default_info["timezone"] = blade_info.time_zone
        if DRIVES_API_VERSION in api_version:
            default_info["product_type"] = getattr(
                blade_info, "product_type", "Unknown"
            )
        if SECURITY_API_VERSION in api_version:
            dar = blade_info.encryption.data_at_rest
            default_info["encryption"] = {
                "data_at_rest_enabled": dar.enabled,
                "data_at_rest_algorithms": dar.algorithms,
                "data_at_rest_entropy_source": dar.entropy_source,
            }
            keys = list(blade.get_support_verification_keys().items)
            default_info["support_keys"] = {}
            for key in range(0, len(keys)):
                keyname = keys[key].name
                default_info["support_keys"][keyname] = {keys[key].verification_key}
            default_info["security_update"] = getattr(
                blade_info, "security_update", None
            )

    return default_info


def generate_perf_dict(blade):
    perf_info = {}
    total_perf = blade.arrays.list_arrays_performance()
    http_perf = blade.arrays.list_arrays_performance(protocol="http")
    s3_perf = blade.arrays.list_arrays_performance(protocol="s3")
    nfs_perf = blade.arrays.list_arrays_performance(protocol="nfs")
    perf_info["aggregate"] = {
        "bytes_per_op": total_perf.items[0].bytes_per_op,
        "bytes_per_read": total_perf.items[0].bytes_per_read,
        "bytes_per_write": total_perf.items[0].bytes_per_write,
        "read_bytes_per_sec": total_perf.items[0].read_bytes_per_sec,
        "reads_per_sec": total_perf.items[0].reads_per_sec,
        "usec_per_other_op": total_perf.items[0].usec_per_other_op,
        "usec_per_read_op": total_perf.items[0].usec_per_read_op,
        "usec_per_write_op": total_perf.items[0].usec_per_write_op,
        "write_bytes_per_sec": total_perf.items[0].write_bytes_per_sec,
        "writes_per_sec": total_perf.items[0].writes_per_sec,
    }
    perf_info["http"] = {
        "bytes_per_op": http_perf.items[0].bytes_per_op,
        "bytes_per_read": http_perf.items[0].bytes_per_read,
        "bytes_per_write": http_perf.items[0].bytes_per_write,
        "read_bytes_per_sec": http_perf.items[0].read_bytes_per_sec,
        "reads_per_sec": http_perf.items[0].reads_per_sec,
        "usec_per_other_op": http_perf.items[0].usec_per_other_op,
        "usec_per_read_op": http_perf.items[0].usec_per_read_op,
        "usec_per_write_op": http_perf.items[0].usec_per_write_op,
        "write_bytes_per_sec": http_perf.items[0].write_bytes_per_sec,
        "writes_per_sec": http_perf.items[0].writes_per_sec,
    }
    perf_info["s3"] = {
        "bytes_per_op": s3_perf.items[0].bytes_per_op,
        "bytes_per_read": s3_perf.items[0].bytes_per_read,
        "bytes_per_write": s3_perf.items[0].bytes_per_write,
        "read_bytes_per_sec": s3_perf.items[0].read_bytes_per_sec,
        "reads_per_sec": s3_perf.items[0].reads_per_sec,
        "usec_per_other_op": s3_perf.items[0].usec_per_other_op,
        "usec_per_read_op": s3_perf.items[0].usec_per_read_op,
        "usec_per_write_op": s3_perf.items[0].usec_per_write_op,
        "write_bytes_per_sec": s3_perf.items[0].write_bytes_per_sec,
        "writes_per_sec": s3_perf.items[0].writes_per_sec,
    }
    perf_info["nfs"] = {
        "bytes_per_op": nfs_perf.items[0].bytes_per_op,
        "bytes_per_read": nfs_perf.items[0].bytes_per_read,
        "bytes_per_write": nfs_perf.items[0].bytes_per_write,
        "read_bytes_per_sec": nfs_perf.items[0].read_bytes_per_sec,
        "reads_per_sec": nfs_perf.items[0].reads_per_sec,
        "usec_per_other_op": nfs_perf.items[0].usec_per_other_op,
        "usec_per_read_op": nfs_perf.items[0].usec_per_read_op,
        "usec_per_write_op": nfs_perf.items[0].usec_per_write_op,
        "write_bytes_per_sec": nfs_perf.items[0].write_bytes_per_sec,
        "writes_per_sec": nfs_perf.items[0].writes_per_sec,
    }
    api_version = blade.api_version.list_versions().versions
    if REPLICATION_API_VERSION in api_version:
        file_repl_perf = (
            blade.array_connections.list_array_connections_performance_replication(
                type="file-system"
            )
        )
        obj_repl_perf = (
            blade.array_connections.list_array_connections_performance_replication(
                type="object-store"
            )
        )
        if len(file_repl_perf.total):
            perf_info["file_replication"] = {
                "received_bytes_per_sec": file_repl_perf.total[
                    0
                ].periodic.received_bytes_per_sec,
                "transmitted_bytes_per_sec": file_repl_perf.total[
                    0
                ].periodic.transmitted_bytes_per_sec,
            }
        if len(obj_repl_perf.total):
            perf_info["object_replication"] = {
                "received_bytes_per_sec": obj_repl_perf.total[
                    0
                ].periodic.received_bytes_per_sec,
                "transmitted_bytes_per_sec": obj_repl_perf.total[
                    0
                ].periodic.transmitted_bytes_per_sec,
            }
    return perf_info


def generate_config_dict(blade):
    config_info = {}
    config_info["dns"] = blade.dns.list_dns().items[0].to_dict()
    config_info["smtp"] = blade.smtp.list_smtp().items[0].to_dict()
    try:
        config_info["alert_watchers"] = (
            blade.alert_watchers.list_alert_watchers().items[0].to_dict()
        )
    except Exception:
        config_info["alert_watchers"] = ""
    api_version = blade.api_version.list_versions().versions
    if HARD_LIMIT_API_VERSION in api_version:
        config_info["array_management"] = (
            blade.directory_services.list_directory_services(names=["management"])
            .items[0]
            .to_dict()
        )
        config_info["directory_service_roles"] = {}
        roles = blade.directory_services.list_directory_services_roles()
        for role in range(0, len(roles.items)):
            role_name = roles.items[role].name
            config_info["directory_service_roles"][role_name] = {
                "group": roles.items[role].group,
                "group_base": roles.items[role].group_base,
            }
    config_info["nfs_directory_service"] = (
        blade.directory_services.list_directory_services(names=["nfs"])
        .items[0]
        .to_dict()
    )
    config_info["smb_directory_service"] = (
        blade.directory_services.list_directory_services(names=["smb"])
        .items[0]
        .to_dict()
    )
    config_info["ntp"] = blade.arrays.list_arrays().items[0].ntp_servers
    config_info["ssl_certs"] = blade.certificates.list_certificates().items[0].to_dict()
    api_version = blade.api_version.list_versions().versions
    if CERT_GROUPS_API_VERSION in api_version:
        try:
            config_info["certificate_groups"] = (
                blade.certificate_groups.list_certificate_groups().items[0].to_dict()
            )
        except Exception:
            config_info["certificate_groups"] = ""
    if REPLICATION_API_VERSION in api_version:
        config_info["snmp_agents"] = {}
        snmp_agents = blade.snmp_agents.list_snmp_agents()
        for agent in range(0, len(snmp_agents.items)):
            agent_name = snmp_agents.items[agent].name
            config_info["snmp_agents"][agent_name] = {
                "version": snmp_agents.items[agent].version,
                "engine_id": snmp_agents.items[agent].engine_id,
            }
            if config_info["snmp_agents"][agent_name]["version"] == "v3":
                config_info["snmp_agents"][agent_name][
                    "auth_protocol"
                ] = snmp_agents.items[agent].v3.auth_protocol
                config_info["snmp_agents"][agent_name][
                    "privacy_protocol"
                ] = snmp_agents.items[agent].v3.privacy_protocol
                config_info["snmp_agents"][agent_name]["user"] = snmp_agents.items[
                    agent
                ].v3.user
        config_info["snmp_managers"] = {}
        snmp_managers = blade.snmp_managers.list_snmp_managers()
        for manager in range(0, len(snmp_managers.items)):
            mgr_name = snmp_managers.items[manager].name
            config_info["snmp_managers"][mgr_name] = {
                "version": snmp_managers.items[manager].version,
                "host": snmp_managers.items[manager].host,
                "notification": snmp_managers.items[manager].notification,
            }
            if config_info["snmp_managers"][mgr_name]["version"] == "v3":
                config_info["snmp_managers"][mgr_name][
                    "auth_protocol"
                ] = snmp_managers.items[manager].v3.auth_protocol
                config_info["snmp_managers"][mgr_name][
                    "privacy_protocol"
                ] = snmp_managers.items[manager].v3.privacy_protocol
                config_info["snmp_managers"][mgr_name]["user"] = snmp_managers.items[
                    manager
                ].v3.user
    return config_info


def generate_subnet_dict(blade):
    sub_info = {}
    subnets = blade.subnets.list_subnets()
    for sub in range(0, len(subnets.items)):
        sub_name = subnets.items[sub].name
        if subnets.items[sub].enabled:
            sub_info[sub_name] = {
                "gateway": subnets.items[sub].gateway,
                "mtu": subnets.items[sub].mtu,
                "vlan": subnets.items[sub].vlan,
                "prefix": subnets.items[sub].prefix,
                "services": subnets.items[sub].services,
            }
            sub_info[sub_name]["lag"] = subnets.items[sub].link_aggregation_group.name
            sub_info[sub_name]["interfaces"] = []
            for iface in range(0, len(subnets.items[sub].interfaces)):
                sub_info[sub_name]["interfaces"].append(
                    {"name": subnets.items[sub].interfaces[iface].name}
                )
    return sub_info


def generate_lag_dict(blade):
    lag_info = {}
    groups = blade.link_aggregation_groups.list_link_aggregation_groups()
    for groupcnt in range(0, len(groups.items)):
        lag_name = groups.items[groupcnt].name
        lag_info[lag_name] = {
            "lag_speed": groups.items[groupcnt].lag_speed,
            "port_speed": groups.items[groupcnt].port_speed,
            "status": groups.items[groupcnt].status,
        }
        lag_info[lag_name]["ports"] = []
        for port in range(0, len(groups.items[groupcnt].ports)):
            lag_info[lag_name]["ports"].append(
                {"name": groups.items[groupcnt].ports[port].name}
            )
    return lag_info


def generate_admin_dict(module, blade):
    admin_info = {}
    api_version = blade.api_version.list_versions().versions
    if MULTIPROTOCOL_API_VERSION in api_version:
        admins = blade.admins.list_admins()
        for admin in range(0, len(admins.items)):
            admin_name = admins.items[admin].name
            admin_info[admin_name] = {
                "api_token_timeout": admins.items[admin].api_token_timeout,
                "public_key": admins.items[admin].public_key,
                "local": admins.items[admin].is_local,
            }

    if MIN_32_API in api_version:
        bladev2 = get_system(module)
        admins = list(bladev2.get_admins().items)
        for admin in range(0, len(admins)):
            admin_name = admins[admin].name
            if admins[admin].api_token.expires_at:
                admin_info[admin_name]["token_expires"] = datetime.fromtimestamp(
                    admins[admin].api_token.expires_at / 1000
                ).strftime("%Y-%m-%d %H:%M:%S")
            else:
                admin_info[admin_name]["token_expires"] = None
            admin_info[admin_name]["token_created"] = datetime.fromtimestamp(
                admins[admin].api_token.created_at / 1000
            ).strftime("%Y-%m-%d %H:%M:%S")
            admin_info[admin_name]["role"] = admins[admin].role.name
            if NFS_POLICY_API_VERSION in api_version:
                admin_info[admin_name]["locked"] = admins[admin].locked
                admin_info[admin_name]["lockout_remaining"] = admins[
                    admin
                ].lockout_remaining
    return admin_info


def generate_targets_dict(blade):
    targets_info = {}
    targets = blade.targets.list_targets()
    for target in range(0, len(targets.items)):
        target_name = targets.items[target].name
        targets_info[target_name] = {
            "address": targets.items[target].address,
            "status": targets.items[target].status,
            "status_details": targets.items[target].status_details,
        }
    return targets_info


def generate_remote_creds_dict(blade):
    remote_creds_info = {}
    remote_creds = (
        blade.object_store_remote_credentials.list_object_store_remote_credentials()
    )
    for cred_cnt in range(0, len(remote_creds.items)):
        cred_name = remote_creds.items[cred_cnt].name
        remote_creds_info[cred_name] = {
            "access_key": remote_creds.items[cred_cnt].access_key_id,
            "remote_array": remote_creds.items[cred_cnt].remote.name,
        }
    return remote_creds_info


def generate_file_repl_dict(blade):
    file_repl_info = {}
    file_links = blade.file_system_replica_links.list_file_system_replica_links()
    for linkcnt in range(0, len(file_links.items)):
        fs_name = file_links.items[linkcnt].local_file_system.name
        file_repl_info[fs_name] = {
            "direction": file_links.items[linkcnt].direction,
            "lag": file_links.items[linkcnt].lag,
            "status": file_links.items[linkcnt].status,
            "remote_fs": file_links.items[linkcnt].remote.name
            + ":"
            + file_links.items[linkcnt].remote_file_system.name,
            "recovery_point": file_links.items[linkcnt].recovery_point,
        }
        file_repl_info[fs_name]["policies"] = []
        for policy_cnt in range(0, len(file_links.items[linkcnt].policies)):
            file_repl_info[fs_name]["policies"].append(
                file_links.items[linkcnt].policies[policy_cnt].display_name
            )
    return file_repl_info


def generate_bucket_repl_dict(module, blade):
    bucket_repl_info = {}
    bucket_links = blade.bucket_replica_links.list_bucket_replica_links()
    for linkcnt in range(0, len(bucket_links.items)):
        bucket_name = bucket_links.items[linkcnt].local_bucket.name
        bucket_repl_info[bucket_name] = {
            "direction": bucket_links.items[linkcnt].direction,
            "lag": bucket_links.items[linkcnt].lag,
            "paused": bucket_links.items[linkcnt].paused,
            "status": bucket_links.items[linkcnt].status,
            "remote_bucket": bucket_links.items[linkcnt].remote_bucket.name,
            "remote_credentials": bucket_links.items[linkcnt].remote_credentials.name,
            "recovery_point": bucket_links.items[linkcnt].recovery_point,
            "object_backlog": {},
        }
    api_version = blade.api_version.list_versions().versions
    if SMB_MODE_API_VERSION in api_version:
        blade = get_system(module)
        bucket_links = list(blade.get_bucket_replica_links().items)
        for linkcnt in range(0, len(bucket_links)):
            bucket_name = bucket_links[linkcnt].local_bucket.name
            bucket_repl_info[bucket_name]["object_backlog"] = {
                "bytes_count": bucket_links[linkcnt].object_backlog.bytes_count,
                "delete_ops_count": bucket_links[
                    linkcnt
                ].object_backlog.delete_ops_count,
                "other_ops_count": bucket_links[linkcnt].object_backlog.other_ops_count,
                "put_ops_count": bucket_links[linkcnt].object_backlog.put_ops_count,
            }
            bucket_repl_info[bucket_name]["cascading_enabled"] = bucket_links[
                linkcnt
            ].cascading_enabled
    return bucket_repl_info


def generate_network_dict(blade):
    net_info = {}
    ports = blade.network_interfaces.list_network_interfaces()
    for portcnt in range(0, len(ports.items)):
        int_name = ports.items[portcnt].name
        if ports.items[portcnt].enabled:
            net_info[int_name] = {
                "type": ports.items[portcnt].type,
                "mtu": ports.items[portcnt].mtu,
                "vlan": ports.items[portcnt].vlan,
                "address": ports.items[portcnt].address,
                "services": ports.items[portcnt].services,
                "gateway": ports.items[portcnt].gateway,
                "netmask": ports.items[portcnt].netmask,
            }
    return net_info


def generate_capacity_dict(blade):
    capacity_info = {}
    total_cap = blade.arrays.list_arrays_space()
    file_cap = blade.arrays.list_arrays_space(type="file-system")
    object_cap = blade.arrays.list_arrays_space(type="object-store")
    capacity_info["total"] = total_cap.items[0].capacity
    capacity_info["aggregate"] = {
        "data_reduction": total_cap.items[0].space.data_reduction,
        "snapshots": total_cap.items[0].space.snapshots,
        "total_physical": total_cap.items[0].space.total_physical,
        "unique": total_cap.items[0].space.unique,
        "virtual": total_cap.items[0].space.virtual,
    }
    capacity_info["file-system"] = {
        "data_reduction": file_cap.items[0].space.data_reduction,
        "snapshots": file_cap.items[0].space.snapshots,
        "total_physical": file_cap.items[0].space.total_physical,
        "unique": file_cap.items[0].space.unique,
        "virtual": file_cap.items[0].space.virtual,
    }
    capacity_info["object-store"] = {
        "data_reduction": object_cap.items[0].space.data_reduction,
        "snapshots": object_cap.items[0].space.snapshots,
        "total_physical": object_cap.items[0].space.total_physical,
        "unique": object_cap.items[0].space.unique,
        "virtual": file_cap.items[0].space.virtual,
    }

    return capacity_info


def generate_snap_dict(blade):
    snap_info = {}
    snaps = blade.file_system_snapshots.list_file_system_snapshots()
    api_version = blade.api_version.list_versions().versions
    for snap in range(0, len(snaps.items)):
        snapshot = snaps.items[snap].name
        snap_info[snapshot] = {
            "destroyed": snaps.items[snap].destroyed,
            "source": snaps.items[snap].source,
            "suffix": snaps.items[snap].suffix,
            "source_destroyed": snaps.items[snap].source_destroyed,
        }
        if REPLICATION_API_VERSION in api_version:
            snap_info[snapshot]["owner"] = snaps.items[snap].owner.name
            snap_info[snapshot]["owner_destroyed"] = snaps.items[snap].owner_destroyed
            snap_info[snapshot]["source_display_name"] = snaps.items[
                snap
            ].source_display_name
            snap_info[snapshot]["source_is_local"] = snaps.items[snap].source_is_local
            snap_info[snapshot]["source_location"] = snaps.items[
                snap
            ].source_location.name
    return snap_info


def generate_snap_transfer_dict(blade):
    snap_transfer_info = {}
    snap_transfers = blade.file_system_snapshots.list_file_system_snapshots_transfer()
    for snap_transfer in range(0, len(snap_transfers.items)):
        transfer = snap_transfers.items[snap_transfer].name
        snap_transfer_info[transfer] = {
            "completed": snap_transfers.items[snap_transfer].completed,
            "data_transferred": snap_transfers.items[snap_transfer].data_transferred,
            "progress": snap_transfers.items[snap_transfer].progress,
            "direction": snap_transfers.items[snap_transfer].direction,
            "remote": snap_transfers.items[snap_transfer].remote.name,
            "remote_snapshot": snap_transfers.items[snap_transfer].remote_snapshot.name,
            "started": snap_transfers.items[snap_transfer].started,
            "status": snap_transfers.items[snap_transfer].status,
        }
    return snap_transfer_info


def generate_array_conn_dict(module, blade):
    array_conn_info = {}
    arraysv2 = {}
    api_version = blade.api_version.list_versions().versions
    arrays = blade.array_connections.list_array_connections()
    if NFS_POLICY_API_VERSION in api_version:
        bladev2 = get_system(module)
        arraysv2 = list(bladev2.get_array_connections().items)
    for arraycnt in range(0, len(arrays.items)):
        array = arrays.items[arraycnt].remote.name
        array_conn_info[array] = {
            "encrypted": arrays.items[arraycnt].encrypted,
            "replication_addresses": arrays.items[arraycnt].replication_addresses,
            "management_address": arrays.items[arraycnt].management_address,
            "status": arrays.items[arraycnt].status,
            "version": arrays.items[arraycnt].version,
            "throttle": [],
        }
        if arrays.items[arraycnt].encrypted:
            array_conn_info[array]["ca_certificate_group"] = arrays.items[
                arraycnt
            ].ca_certificate_group.name
        for v2array in range(0, len(arraysv2)):
            if arraysv2[v2array].remote.name == array:
                array_conn_info[array]["throttle"] = {
                    "default_limit": _bytes_to_human(
                        arraysv2[v2array].throttle.default_limit
                    ),
                    "window_limit": _bytes_to_human(
                        arraysv2[v2array].throttle.window_limit
                    ),
                    "window_start": _millisecs_to_time(
                        arraysv2[v2array].throttle.window.start
                    ),
                    "window_end": _millisecs_to_time(
                        arraysv2[v2array].throttle.window.end
                    ),
                }
    return array_conn_info


def generate_policies_dict(blade):
    policies_info = {}
    policies = blade.policies.list_policies()
    for policycnt in range(0, len(policies.items)):
        policy = policies.items[policycnt].name
        policies_info[policy] = {}
        policies_info[policy]["enabled"] = policies.items[policycnt].enabled
        if policies.items[policycnt].rules:
            policies_info[policy]["rules"] = (
                policies.items[policycnt].rules[0].to_dict()
            )
    return policies_info


def generate_bucket_dict(module, blade):
    bucket_info = {}
    buckets = blade.buckets.list_buckets()
    for bckt in range(0, len(buckets.items)):
        bucket = buckets.items[bckt].name
        bucket_info[bucket] = {
            "versioning": buckets.items[bckt].versioning,
            "bucket_type": getattr(buckets.items[bckt], "bucket_type", None),
            "object_count": buckets.items[bckt].object_count,
            "id": buckets.items[bckt].id,
            "account_name": buckets.items[bckt].account.name,
            "data_reduction": buckets.items[bckt].space.data_reduction,
            "snapshot_space": buckets.items[bckt].space.snapshots,
            "total_physical_space": buckets.items[bckt].space.total_physical,
            "unique_space": buckets.items[bckt].space.unique,
            "virtual_space": buckets.items[bckt].space.virtual,
            "created": buckets.items[bckt].created,
            "destroyed": buckets.items[bckt].destroyed,
            "time_remaining": buckets.items[bckt].time_remaining,
            "lifecycle_rules": {},
        }
    api_version = blade.api_version.list_versions().versions
    if LIFECYCLE_API_VERSION in api_version:
        blade = get_system(module)
        for bckt in range(0, len(buckets.items)):
            if buckets.items[bckt].destroyed:
                # skip processing buckets marked as destroyed
                continue
            all_rules = list(
                blade.get_lifecycle_rules(bucket_ids=[buckets.items[bckt].id]).items
            )
            for rule in range(0, len(all_rules)):
                bucket_name = all_rules[rule].bucket.name
                rule_id = all_rules[rule].rule_id
                if all_rules[rule].keep_previous_version_for:
                    keep_previous_version_for = int(
                        all_rules[rule].keep_previous_version_for / 86400000
                    )
                else:
                    keep_previous_version_for = None
                if all_rules[rule].keep_current_version_for:
                    keep_current_version_for = int(
                        all_rules[rule].keep_current_version_for / 86400000
                    )
                else:
                    keep_current_version_for = None
                if all_rules[rule].abort_incomplete_multipart_uploads_after:
                    abort_incomplete_multipart_uploads_after = int(
                        all_rules[rule].abort_incomplete_multipart_uploads_after
                        / 86400000
                    )
                else:
                    abort_incomplete_multipart_uploads_after = None
                if all_rules[rule].keep_current_version_until:
                    keep_current_version_until = datetime.fromtimestamp(
                        all_rules[rule].keep_current_version_until / 1000
                    ).strftime("%Y-%m-%d")
                else:
                    keep_current_version_until = None
                bucket_info[bucket_name]["lifecycle_rules"][rule_id] = {
                    "keep_previous_version_for (days)": keep_previous_version_for,
                    "keep_current_version_for (days)": keep_current_version_for,
                    "keep_current_version_until": keep_current_version_until,
                    "prefix": all_rules[rule].prefix,
                    "enabled": all_rules[rule].enabled,
                    "abort_incomplete_multipart_uploads_after (days)": abort_incomplete_multipart_uploads_after,
                    "cleanup_expired_object_delete_marker": all_rules[
                        rule
                    ].cleanup_expired_object_delete_marker,
                }
        if VSO_VERSION in api_version:
            buckets = list(blade.get_buckets().items)
            for bucket in range(0, len(buckets)):
                bucket_info[buckets[bucket].name]["bucket_type"] = buckets[
                    bucket
                ].bucket_type
            if BUCKET_API_VERSION in api_version:
                for bucket in range(0, len(buckets)):
                    bucket_info[buckets[bucket].name]["retention_lock"] = buckets[
                        bucket
                    ].retention_lock
                    bucket_info[buckets[bucket].name]["quota_limit"] = buckets[
                        bucket
                    ].quota_limit
                    bucket_info[buckets[bucket].name]["object_lock_config"] = {
                        "enabled": buckets[bucket].object_lock_config.enabled,
                        "freeze_locked_objects": buckets[
                            bucket
                        ].object_lock_config.freeze_locked_objects,
                    }
                    bucket_info[buckets[bucket].name]["eradication_config"] = {
                        "eradication_delay": buckets[
                            bucket
                        ].eradication_config.eradication_delay,
                        "manual_eradication": buckets[
                            bucket
                        ].eradication_config.manual_eradication,
                    }
    return bucket_info


def generate_kerb_dict(blade):
    kerb_info = {}
    keytabs = list(blade.get_keytabs().items)
    for ktab in range(0, len(keytabs)):
        keytab_name = keytabs[ktab].prefix
        kerb_info[keytab_name] = {}
        for key in range(0, len(keytabs)):
            if keytabs[key].prefix == keytab_name:
                kerb_info[keytab_name][keytabs[key].suffix] = {
                    "fqdn": keytabs[key].fqdn,
                    "kvno": keytabs[key].kvno,
                    "principal": keytabs[key].principal,
                    "realm": keytabs[key].realm,
                    "encryption_type": keytabs[key].encryption_type,
                }
    return kerb_info


def generate_ad_dict(blade):
    ad_info = {}
    active_directory = blade.get_active_directory()
    if active_directory.total_item_count != 0:
        ad_account = list(active_directory.items)[0]
        ad_info[ad_account.name] = {
            "computer": ad_account.computer_name,
            "domain": ad_account.domain,
            "directory_servers": ad_account.directory_servers,
            "kerberos_servers": ad_account.kerberos_servers,
            "service_principals": ad_account.service_principal_names,
            "join_ou": ad_account.join_ou,
            "encryption_types": ad_account.encryption_types,
        }
    return ad_info


def generate_object_store_access_policies_dict(blade):
    policies_info = {}
    policies = list(blade.get_object_store_access_policies().items)
    for policy in range(0, len(policies)):
        policy_name = policies[policy].name
        policies_info[policy_name] = {
            "ARN": policies[policy].arn,
            "description": policies[policy].description,
            "enabled": policies[policy].enabled,
            "local": policies[policy].is_local,
            "rules": [],
        }
        for rule in range(0, len(policies[policy].rules)):
            policies_info[policy_name]["rules"].append(
                {
                    "actions": policies[policy].rules[rule].actions,
                    "conditions": {
                        "source_ips": policies[policy]
                        .rules[rule]
                        .conditions.source_ips,
                        "s3_delimiters": policies[policy]
                        .rules[rule]
                        .conditions.s3_delimiters,
                        "s3_prefixes": policies[policy]
                        .rules[rule]
                        .conditions.s3_prefixes,
                    },
                    "effect": policies[policy].rules[rule].effect,
                    "name": policies[policy].rules[rule].name,
                }
            )
    return policies_info


def generate_nfs_export_policies_dict(blade):
    policies_info = {}
    policies = list(blade.get_nfs_export_policies().items)
    for policy in range(0, len(policies)):
        policy_name = policies[policy].name
        policies_info[policy_name] = {
            "local": policies[policy].is_local,
            "enabled": policies[policy].enabled,
            "rules": [],
        }
        for rule in range(0, len(policies[policy].rules)):
            policies_info[policy_name]["rules"].append(
                {
                    "access": policies[policy].rules[rule].access,
                    "anongid": policies[policy].rules[rule].anongid,
                    "anonuid": policies[policy].rules[rule].anonuid,
                    "atime": policies[policy].rules[rule].atime,
                    "client": policies[policy].rules[rule].client,
                    "fileid_32bit": policies[policy].rules[rule].fileid_32bit,
                    "permission": policies[policy].rules[rule].permission,
                    "secure": policies[policy].rules[rule].secure,
                    "security": policies[policy].rules[rule].security,
                    "index": policies[policy].rules[rule].index,
                }
            )
    return policies_info


def generate_object_store_accounts_dict(blade):
    account_info = {}
    accounts = list(blade.get_object_store_accounts().items)
    for account in range(0, len(accounts)):
        acc_name = accounts[account].name
        account_info[acc_name] = {
            "object_count": accounts[account].object_count,
            "data_reduction": accounts[account].space.data_reduction,
            "snapshots_space": accounts[account].space.snapshots,
            "total_physical_space": accounts[account].space.total_physical,
            "unique_space": accounts[account].space.unique,
            "virtual_space": accounts[account].space.virtual,
            "quota_limit": getattr(accounts[account], "quota_limit", None),
            "hard_limit_enabled": getattr(
                accounts[account], "hard_limit_enabled", None
            ),
            "total_provisioned": getattr(
                accounts[account].space, "total_provisioned", None
            ),
            "users": {},
        }
        try:
            account_info[acc_name]["bucket_defaults"] = {
                "hard_limit_enabled": accounts[
                    account
                ].bucket_defaults.hard_limit_enabled,
                "quota_limit": accounts[account].bucket_defaults.quota_limit,
            }
        except AttributeError:
            pass
        acc_users = list(
            blade.get_object_store_users(filter='name="' + acc_name + '/*"').items
        )
        for acc_user in range(0, len(acc_users)):
            user_name = acc_users[acc_user].name.split("/")[1]
            account_info[acc_name]["users"][user_name] = {"keys": [], "policies": []}
            if (
                blade.get_object_store_access_keys(
                    filter='user.name="' + acc_users[acc_user].name + '"'
                ).total_item_count
                != 0
            ):
                access_keys = list(
                    blade.get_object_store_access_keys(
                        filter='user.name="' + acc_users[acc_user].name + '"'
                    ).items
                )
                for key in range(0, len(access_keys)):
                    account_info[acc_name]["users"][user_name]["keys"].append(
                        {
                            "name": access_keys[key].name,
                            "enabled": bool(access_keys[key].enabled),
                        }
                    )
            if (
                blade.get_object_store_access_policies_object_store_users(
                    member_names=[acc_users[acc_user].name]
                ).total_item_count
                != 0
            ):
                policies = list(
                    blade.get_object_store_access_policies_object_store_users(
                        member_names=[acc_users[acc_user].name]
                    ).items
                )
                for policy in range(0, len(policies)):
                    account_info[acc_name]["users"][user_name]["policies"].append(
                        policies[policy].policy.name
                    )
    return account_info


def generate_fs_dict(module, blade):
    api_version = blade.api_version.list_versions().versions
    if SMB_MODE_API_VERSION in api_version:
        bladev2 = get_system(module)
        fsys_v2 = list(bladev2.get_file_systems().items)
    fs_info = {}
    fsys = blade.file_systems.list_file_systems()
    for fsystem in range(0, len(fsys.items)):
        share = fsys.items[fsystem].name
        fs_info[share] = {
            "fast_remove": fsys.items[fsystem].fast_remove_directory_enabled,
            "snapshot_enabled": fsys.items[fsystem].snapshot_directory_enabled,
            "provisioned": fsys.items[fsystem].provisioned,
            "destroyed": fsys.items[fsystem].destroyed,
            "nfs_rules": fsys.items[fsystem].nfs.rules,
            "nfs_v3": getattr(fsys.items[fsystem].nfs, "v3_enabled", False),
            "nfs_v4_1": getattr(fsys.items[fsystem].nfs, "v4_1_enabled", False),
            "user_quotas": {},
            "group_quotas": {},
        }
        if fsys.items[fsystem].http.enabled:
            fs_info[share]["http"] = fsys.items[fsystem].http.enabled
        if fsys.items[fsystem].smb.enabled:
            fs_info[share]["smb_mode"] = fsys.items[fsystem].smb.acl_mode
        api_version = blade.api_version.list_versions().versions
        if MULTIPROTOCOL_API_VERSION in api_version:
            fs_info[share]["multi_protocol"] = {
                "safegaurd_acls": fsys.items[fsystem].multi_protocol.safeguard_acls,
                "access_control_style": fsys.items[
                    fsystem
                ].multi_protocol.access_control_style,
            }
        if HARD_LIMIT_API_VERSION in api_version:
            fs_info[share]["hard_limit"] = fsys.items[fsystem].hard_limit_enabled
        if REPLICATION_API_VERSION in api_version:
            fs_info[share]["promotion_status"] = fsys.items[fsystem].promotion_status
            fs_info[share]["requested_promotion_state"] = fsys.items[
                fsystem
            ].requested_promotion_state
            fs_info[share]["writable"] = fsys.items[fsystem].writable
            fs_info[share]["source"] = {
                "is_local": fsys.items[fsystem].source.is_local,
                "name": fsys.items[fsystem].source.name,
            }
        if SMB_MODE_API_VERSION in api_version:
            for v2fs in range(0, len(fsys_v2)):
                if fsys_v2[v2fs].name == share:
                    fs_info[share]["default_group_quota"] = fsys_v2[
                        v2fs
                    ].default_group_quota
                    fs_info[share]["default_user_quota"] = fsys_v2[
                        v2fs
                    ].default_user_quota
                    if NFS_POLICY_API_VERSION in api_version:
                        fs_info[share]["export_policy"] = fsys_v2[
                            v2fs
                        ].nfs.export_policy.name
        if VSO_VERSION in api_version:
            for v2fs in range(0, len(fsys_v2)):
                if fsys_v2[v2fs].name == share:
                    try:
                        fs_groups = True
                        fs_group_quotas = list(
                            bladev2.get_quotas_groups(file_system_names=[share]).items
                        )
                    except Exception:
                        fs_groups = False
                    try:
                        fs_users = True
                        fs_user_quotas = list(
                            bladev2.get_quotas_users(file_system_names=[share]).items
                        )
                    except Exception:
                        fs_users = False
                    if fs_groups:
                        for group_quota in range(0, len(fs_group_quotas)):
                            group_name = fs_group_quotas[group_quota].name.rsplit("/")[
                                1
                            ]
                            fs_info[share]["group_quotas"][group_name] = {
                                "group_id": fs_group_quotas[group_quota].group.id,
                                "group_name": fs_group_quotas[group_quota].group.name,
                                "quota": fs_group_quotas[group_quota].quota,
                                "usage": fs_group_quotas[group_quota].usage,
                            }
                    if fs_users:
                        for user_quota in range(0, len(fs_user_quotas)):
                            user_name = fs_user_quotas[user_quota].name.rsplit("/")[1]
                            fs_info[share]["user_quotas"][user_name] = {
                                "user_id": fs_user_quotas[user_quota].user.id,
                                "user_name": fs_user_quotas[user_quota].user.name,
                                "quota": fs_user_quotas[user_quota].quota,
                                "usage": fs_user_quotas[user_quota].usage,
                            }

    return fs_info


def generate_drives_dict(blade):
    """
    Drives information is only available for the Legend chassis.
    The Legend chassis product_name has // in it so only bother if
    that is the case.
    """
    drives_info = {}
    drives = list(blade.get_drives().items)
    if "//" in list(blade.get_arrays().items)[0].product_type:
        for drive in range(0, len(drives)):
            name = drives[drive].name
            drives_info[name] = {
                "progress": getattr(drives[drive], "progress", None),
                "raw_capacity": getattr(drives[drive], "raw_capacity", None),
                "status": getattr(drives[drive], "status", None),
                "details": getattr(drives[drive], "details", None),
            }
    return drives_info


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(gather_subset=dict(default="minimum", type="list", elements="str"))
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    blade = get_blade(module)
    versions = blade.api_version.list_versions().versions

    if MIN_REQUIRED_API_VERSION not in versions:
        module.fail_json(
            msg="Minimum FlashBlade REST version required: {0}".format(
                MIN_REQUIRED_API_VERSION
            )
        )
    if not module.params["gather_subset"]:
        module.params["gather_subset"] = ["minimum"]
    subset = [test.lower() for test in module.params["gather_subset"]]
    valid_subsets = (
        "all",
        "minimum",
        "config",
        "performance",
        "capacity",
        "network",
        "subnets",
        "lags",
        "filesystems",
        "snapshots",
        "buckets",
        "arrays",
        "replication",
        "policies",
        "accounts",
        "admins",
        "ad",
        "kerberos",
        "drives",
    )
    subset_test = (test in valid_subsets for test in subset)
    if not all(subset_test):
        module.fail_json(
            msg="value must gather_subset must be one or more of: %s, got: %s"
            % (",".join(valid_subsets), ",".join(subset))
        )

    info = {}

    api_version = blade.api_version.list_versions().versions
    if "minimum" in subset or "all" in subset:
        info["default"] = generate_default_dict(module, blade)
    if "performance" in subset or "all" in subset:
        info["performance"] = generate_perf_dict(blade)
    if "config" in subset or "all" in subset:
        info["config"] = generate_config_dict(blade)
    if "capacity" in subset or "all" in subset:
        info["capacity"] = generate_capacity_dict(blade)
    if "lags" in subset or "all" in subset:
        info["lag"] = generate_lag_dict(blade)
    if "network" in subset or "all" in subset:
        info["network"] = generate_network_dict(blade)
    if "subnets" in subset or "all" in subset:
        info["subnet"] = generate_subnet_dict(blade)
    if "filesystems" in subset or "all" in subset:
        info["filesystems"] = generate_fs_dict(module, blade)
    if "admins" in subset or "all" in subset:
        info["admins"] = generate_admin_dict(module, blade)
    if "snapshots" in subset or "all" in subset:
        info["snapshots"] = generate_snap_dict(blade)
    if "buckets" in subset or "all" in subset:
        info["buckets"] = generate_bucket_dict(module, blade)
    if POLICIES_API_VERSION in api_version:
        if "policies" in subset or "all" in subset:
            info["policies"] = generate_policies_dict(blade)
            info["snapshot_policies"] = generate_policies_dict(blade)
    if REPLICATION_API_VERSION in api_version:
        if "arrays" in subset or "all" in subset:
            info["arrays"] = generate_array_conn_dict(module, blade)
        if "replication" in subset or "all" in subset:
            info["file_replication"] = generate_file_repl_dict(blade)
            info["bucket_replication"] = generate_bucket_repl_dict(module, blade)
            info["snap_transfers"] = generate_snap_transfer_dict(blade)
            info["remote_credentials"] = generate_remote_creds_dict(blade)
            info["targets"] = generate_targets_dict(blade)
    if MIN_32_API in api_version:
        # Calls for data only available from Purity//FB 3.2 and higher
        blade = get_system(module)
        if "accounts" in subset or "all" in subset:
            info["accounts"] = generate_object_store_accounts_dict(blade)
        if "ad" in subset or "all" in subset:
            info["active_directory"] = generate_ad_dict(blade)
        if "kerberos" in subset or "all" in subset:
            info["kerberos"] = generate_kerb_dict(blade)
        if "policies" in subset or "all" in subset:
            if SMB_MODE_API_VERSION in api_version:
                info["access_policies"] = generate_object_store_access_policies_dict(
                    blade
                )
            if NFS_POLICY_API_VERSION in api_version:
                info["export_policies"] = generate_nfs_export_policies_dict(blade)
        if "drives" in subset or "all" in subset and DRIVES_API_VERSION in api_version:
            info["drives"] = generate_drives_dict(blade)
    module.exit_json(changed=False, purefb_info=info)


if __name__ == "__main__":
    main()

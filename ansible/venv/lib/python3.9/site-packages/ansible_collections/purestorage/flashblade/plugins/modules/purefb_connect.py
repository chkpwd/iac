#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2020, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: purefb_connect
version_added: '1.0.0'
short_description: Manage replication connections between two FlashBlades
description:
- Manage replication connections to specified remote FlashBlade system
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Create or delete replication connection
    default: present
    type: str
    choices: [ absent, present ]
  encrypted:
    description:
    - Define if replication connection is encrypted
    type: bool
    default: false
  target_url:
    description:
    - Management IP address of target FlashBlade system
    type: str
    required: true
  target_api:
    description:
    - API token for target FlashBlade system
    type: str
  target_repl:
    description:
    - Replication IP address of target FlashBlade system
    - If not set at time of connection creation, will default to
      all the replication addresses available on the target array
      at the time of connection creation.
    type: list
    elements: str
    version_added: "1.9.0"
  default_limit:
    description:
    - Default maximum bandwidth threshold for outbound traffic in bytes.
    - B, K, M, or G units. See examples.
    - Must be 0 or between 5MB and 28GB
    - Once exceeded, bandwidth throttling occurs
    type: str
    version_added: "1.9.0"
  window_limit:
    description:
    - Maximum bandwidth threshold for outbound traffic during the specified
      time range in bytes.
    - B, K, M, or G units. See examples.
    - Must be 0 or between 5MB and 28GB
    - Once exceeded, bandwidth throttling occurs
    type: str
    version_added: "1.9.0"
  window_start:
    description:
    - The window start time.
    - The time must be set to the hour.
    type: str
    version_added: "1.9.0"
  window_end:
    description:
    - The window end time.
    - The time must be set to the hour.
    type: str
    version_added: "1.9.0"
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Create a connection to remote FlashBlade system
  purestorage.flashblade.purefb_connect:
    target_url: 10.10.10.20
    target_api: T-b3275b1c-8958-4190-9052-eb46b0bd09f8
    fb_url: 10.10.10.2
    api_token: T-91528421-fe42-47ee-bcb1-47eefb0a9220
- name: Create a connection to remote FlashBlade system with bandwidth limits
  purestorage.flashblade.purefb_connect:
    target_url: 10.10.10.20
    target_api: T-b3275b1c-8958-4190-9052-eb46b0bd09f8
    window_limit: 28G
    window_start: 1AM
    window_end: 7AM
    default_limit: 5M
    fb_url: 10.10.10.2
    api_token: T-91528421-fe42-47ee-bcb1-47eefb0a9220
- name: Delete connection to target FlashBlade system
  purestorage.flashblade.purefb_connect:
    state: absent
    target_url: 10.10.10.20
    target_api: T-b3275b1c-8958-4190-9052-eb46b0bd09f8
    fb_url: 10.10.10.2
    api_token: T-91528421-fe42-47ee-bcb1-47eefb0a9220
"""

RETURN = r"""
"""

HAS_PURITYFB = True
try:
    from purity_fb import PurityFb, ArrayConnection, ArrayConnectionPost
except ImportError:
    HAS_PURITYFB = False

HAS_PYPURECLIENT = True
try:
    from pypureclient import flashblade
    from pypureclient.flashblade import ArrayConnection, ArrayConnectionPost
except ImportError:
    HAS_PYPURECLIENT = False

from ansible.module_utils.basic import AnsibleModule, human_to_bytes
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_blade,
    get_system,
    purefb_argument_spec,
)


FAN_IN_MAXIMUM = 1
FAN_OUT_MAXIMUM = 3
MIN_REQUIRED_API_VERSION = "1.9"
THROTTLE_API_VERSION = "2.3"


def _convert_to_millisecs(hour):
    if hour[-2:] == "AM" and hour[:2] == "12":
        return 0
    elif hour[-2:] == "AM":
        return int(hour[:-2]) * 3600000
    elif hour[-2:] == "PM" and hour[:2] == "12":
        return 43200000
    return (int(hour[:-2]) + 12) * 3600000


def _check_connected(module, blade):
    connected_blades = blade.array_connections.list_array_connections()
    for target in range(0, len(connected_blades.items)):
        if connected_blades.items[target].management_address is None:
            try:
                remote_system = PurityFb(module.params["target_url"])
                remote_system.login(module.params["target_api"])
                remote_array = remote_system.arrays.list_arrays().items[0].name
                if connected_blades.items[target].remote.name == remote_array:
                    return connected_blades.items[target]
            except Exception:
                module.fail_json(
                    msg="Failed to connect to remote array {0}.".format(
                        module.params["target_url"]
                    )
                )
        if connected_blades.items[target].management_address == module.params[
            "target_url"
        ] and connected_blades.items[target].status in [
            "connected",
            "connecting",
            "partially_connected",
        ]:
            return connected_blades.items[target]
    return None


def break_connection(module, blade, target_blade):
    """Break connection between arrays"""
    changed = True
    if not module.check_mode:
        source_blade = blade.arrays.list_arrays().items[0].name
        try:
            if target_blade.management_address is None:
                module.fail_json(
                    msg="Disconnect can only happen from the array that formed the connection"
                )
            blade.array_connections.delete_array_connections(
                remote_names=[target_blade.remote.name]
            )
        except Exception:
            module.fail_json(
                msg="Failed to disconnect {0} from {1}.".format(
                    target_blade.remote.name, source_blade
                )
            )
    module.exit_json(changed=changed)


def create_connection(module, blade):
    """Create connection between arrays"""
    changed = True
    if not module.check_mode:
        remote_array = module.params["target_url"]
        try:
            remote_system = PurityFb(module.params["target_url"])
            remote_system.login(module.params["target_api"])
            remote_array = remote_system.arrays.list_arrays().items[0].name
            remote_conn_cnt = (
                remote_system.array_connections.list_array_connections().pagination_info.total_item_count
            )
            if remote_conn_cnt == FAN_IN_MAXIMUM:
                module.fail_json(
                    msg="Remote array {0} already connected to {1} other array. Fan-In not supported".format(
                        remote_array, remote_conn_cnt
                    )
                )
            connection_key = (
                remote_system.array_connections.create_array_connections_connection_keys()
                .items[0]
                .connection_key
            )
            connection_info = ArrayConnectionPost(
                management_address=module.params["target_url"],
                encrypted=module.params["encrypted"],
                connection_key=connection_key,
            )
            blade.array_connections.create_array_connections(
                array_connection=connection_info
            )
        except Exception:
            module.fail_json(
                msg="Failed to connect to remote array {0}.".format(remote_array)
            )
    module.exit_json(changed=changed)


def create_v2_connection(module, blade):
    """Create connection between REST 2 capable arrays"""
    changed = True
    if blade.get_array_connections().total_item_count == FAN_OUT_MAXIMUM:
        module.fail_json(
            msg="FlashBlade fan-out maximum of {0} already reached".format(
                FAN_OUT_MAXIMUM
            )
        )
    try:
        remote_system = flashblade.Client(
            target=module.params["target_url"], api_token=module.params["target_api"]
        )
    except Exception:
        module.fail_json(
            msg="Failed to connect to remote array {0}.".format(
                module.params["target_url"]
            )
        )
    remote_array = list(remote_system.get_arrays().items)[0].name
    remote_conn_cnt = remote_system.get_array_connections().total_item_count
    if remote_conn_cnt == FAN_IN_MAXIMUM:
        module.fail_json(
            msg="Remote array {0} already connected to {1} other array. Fan-In not supported".format(
                remote_array, remote_conn_cnt
            )
        )
    connection_key = list(remote_system.post_array_connections_connection_key().items)[
        0
    ].connection_key

    if module.params["default_limit"] or module.params["window_limit"]:
        if THROTTLE_API_VERSION in list(blade.get_versions().items):
            if THROTTLE_API_VERSION not in list(remote_system.get_versions().items):
                module.fail_json(msg="Remote array does not support throttling")
            if module.params["window_limit"]:
                if not module.params["window_start"]:
                    module.params["window_start"] = "12AM"
                if not module.params["window_end"]:
                    module.params["window_end"] = "12AM"
                window = flashblade.TimeWindow(
                    start=_convert_to_millisecs(module.params["window_start"]),
                    end=_convert_to_millisecs(module.params["window_end"]),
                )
            if module.params["window_limit"] and module.params["default_limit"]:
                throttle = flashblade.Throttle(
                    default_limit=human_to_bytes(module.params["default_limit"]),
                    window_limit=human_to_bytes(module.params["window_limit"]),
                    window=window,
                )
            elif module.params["window_limit"] and not module.params["default_limit"]:
                throttle = flashblade.Throttle(
                    window_limit=human_to_bytes(module.params["window_limit"]),
                    window=window,
                )
            else:
                throttle = flashblade.Throttle(
                    default_limit=human_to_bytes(module.params["default_limit"]),
                )
            connection_info = ArrayConnectionPost(
                management_address=module.params["target_url"],
                replication_addresses=module.params["target_repl"],
                encrypted=module.params["encrypted"],
                connection_key=connection_key,
                throttle=throttle,
            )
        else:
            connection_info = ArrayConnectionPost(
                management_address=module.params["target_url"],
                replication_addresses=module.params["target_repl"],
                encrypted=module.params["encrypted"],
                connection_key=connection_key,
            )
    else:
        connection_info = ArrayConnectionPost(
            management_address=module.params["target_url"],
            replication_addresses=module.params["target_repl"],
            encrypted=module.params["encrypted"],
            connection_key=connection_key,
        )
    if not module.check_mode:
        res = blade.post_array_connections(array_connection=connection_info)
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to connect to remote array {0}. Error: {1}".format(
                    remote_array, res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def update_connection(module, blade, target_blade):
    """Update array connection - only encryption currently"""
    changed = False
    if target_blade.management_address is None:
        module.fail_json(
            msg="Update can only happen from the array that formed the connection"
        )
    if module.params["encrypted"] != target_blade.encrypted:
        if (
            module.params["encrypted"]
            and blade.file_system_replica_links.list_file_system_replica_links().pagination_info.total_item_count
            != 0
        ):
            module.fail_json(
                msg="Cannot turn array connection encryption on if file system replica links exist"
            )
        new_attr = ArrayConnection(encrypted=module.params["encrypted"])
        changed = True
        if not module.check_mode:
            try:
                blade.array_connections.update_array_connections(
                    remote_names=[target_blade.remote.name],
                    array_connection=new_attr,
                )
            except Exception:
                module.fail_json(
                    msg="Failed to change encryption setting for array connection."
                )
    module.exit_json(changed=changed)


def update_v2_connection(module, blade):
    """Update REST 2 based array connection"""
    changed = False
    versions = list(blade.get_versions().items)
    remote_blade = flashblade.Client(
        target=module.params["target_url"], api_token=module.params["target_api"]
    )
    remote_name = list(remote_blade.get_arrays().items)[0].name
    remote_connection = list(
        blade.get_array_connections(filter="remote.name='" + remote_name + "'").items
    )[0]
    if remote_connection.management_address is None:
        module.fail_json(
            msg="Update can only happen from the array that formed the connection"
        )
    if module.params["encrypted"] != remote_connection.encrypted:
        if (
            module.params["encrypted"]
            and blade.get_file_system_replica_links().total_item_count != 0
        ):
            module.fail_json(
                msg="Cannot turn array connection encryption on if file system replica links exist"
            )
    current_connection = {
        "encrypted": remote_connection.encrypted,
        "replication_addresses": sorted(remote_connection.replication_addresses),
        "throttle": [],
    }
    if (
        not remote_connection.throttle.default_limit
        and not remote_connection.throttle.window_limit
    ):
        if (
            module.params["default_limit"] or module.params["window_limit"]
        ) and blade.get_bucket_replica_links().total_item_count != 0:
            module.fail_json(
                msg="Cannot set throttle when bucket replica links already exist"
            )
    if THROTTLE_API_VERSION in versions:
        current_connection["throttle"] = {
            "default_limit": remote_connection.throttle.default_limit,
            "window_limit": remote_connection.throttle.window_limit,
            "start": remote_connection.throttle.window.start,
            "end": remote_connection.throttle.window.end,
        }
    if module.params["encrypted"]:
        encryption = module.params["encrypted"]
    else:
        encryption = remote_connection.encrypted
    if module.params["target_repl"]:
        target_repl = sorted(module.params["target_repl"])
    else:
        target_repl = remote_connection.replication_addresses
    if module.params["default_limit"]:
        default_limit = human_to_bytes(module.params["default_limit"])
        if default_limit == 0:
            default_limit = None
    else:
        default_limit = remote_connection.throttle.default_limit
    if module.params["window_limit"]:
        window_limit = human_to_bytes(module.params["window_limit"])
    else:
        window_limit = remote_connection.throttle.window_limit
    if module.params["window_start"]:
        start = _convert_to_millisecs(module.params["window_start"])
    else:
        start = remote_connection.throttle.window.start
    if module.params["window_end"]:
        end = _convert_to_millisecs(module.params["window_end"])
    else:
        end = remote_connection.throttle.window.end

    new_connection = {
        "encrypted": encryption,
        "replication_addresses": target_repl,
        "throttle": [],
    }
    if THROTTLE_API_VERSION in versions:
        new_connection["throttle"] = {
            "default_limit": default_limit,
            "window_limit": window_limit,
            "start": start,
            "end": end,
        }
    if new_connection != current_connection:
        changed = True
        if not module.check_mode:
            if THROTTLE_API_VERSION in versions:
                window = flashblade.TimeWindow(
                    start=new_connection["throttle"]["start"],
                    end=new_connection["throttle"]["end"],
                )
                throttle = flashblade.Throttle(
                    default_limit=new_connection["throttle"]["default_limit"],
                    window_limit=new_connection["throttle"]["window_limit"],
                    window=window,
                )
                connection_info = ArrayConnectionPost(
                    replication_addresses=new_connection["replication_addresses"],
                    encrypted=new_connection["encrypted"],
                    throttle=throttle,
                )
            else:
                connection_info = ArrayConnection(
                    replication_addresses=new_connection["replication_addresses"],
                    encrypted=new_connection["encrypted"],
                )
            res = blade.patch_array_connections(
                remote_names=[remote_name], array_connection=connection_info
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to update connection to remote array {0}. Error: {1}".format(
                        remote_name, res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="present", choices=["absent", "present"]),
            encrypted=dict(type="bool", default=False),
            target_url=dict(type="str", required=True),
            target_api=dict(type="str", no_log=True),
            target_repl=dict(type="list", elements="str"),
            default_limit=dict(type="str"),
            window_limit=dict(type="str"),
            window_start=dict(type="str"),
            window_end=dict(type="str"),
        )
    )

    required_if = [("state", "present", ["target_api"])]

    module = AnsibleModule(
        argument_spec, required_if=required_if, supports_check_mode=True
    )

    if not HAS_PURITYFB:
        module.fail_json(msg="purity_fb sdk is required for this module")

    state = module.params["state"]
    blade = get_blade(module)
    versions = blade.api_version.list_versions().versions

    if MIN_REQUIRED_API_VERSION not in versions:
        module.fail_json(
            msg="Minimum FlashBlade REST version required: {0}".format(
                MIN_REQUIRED_API_VERSION
            )
        )
    if "2.0" in versions:
        bladev2 = get_system(module)
        if not HAS_PYPURECLIENT:
            module.fail_json(msg="py-pure-client sdk is required for this module")
        v2_connection = True
        if module.params["default_limit"]:
            if (
                human_to_bytes(module.params["default_limit"]) != 0
                and 5242880
                >= human_to_bytes(module.params["default_limit"])
                >= 30064771072
            ):
                module.fail_json(msg="Default Bandwidth must be between 5MB and 28GB")
        if module.params["window_limit"]:
            if (
                human_to_bytes(module.params["window_limit"]) != 0
                and 5242880
                >= human_to_bytes(module.params["window_limit"])
                >= 30064771072
            ):
                module.fail_json(msg="Window Bandwidth must be between 5MB and 28GB")
    else:
        if module.params["target_repl"]:
            module.warn(
                "Target Replication addresses can only be set for systems"
                " that support REST 2.0 and higher"
            )
        v2_connection = False

    target_blade = _check_connected(module, blade)
    if state == "present" and not target_blade:
        # REST 1 does not support fan-out for replication
        # REST 2 has a limit which we can check
        if v2_connection:
            create_v2_connection(module, bladev2)
        else:
            if (
                blade.array_connections.list_array_connections().pagination_info.total_item_count
                == 1
            ):
                module.fail_json(
                    msg="Source FlashBlade already connected to another array. Fan-Out not supported"
                )
            create_connection(module, blade)
    elif state == "present" and target_blade:
        if v2_connection:
            update_v2_connection(module, bladev2)
        else:
            update_connection(module, blade, target_blade)
    elif state == "absent" and target_blade:
        break_connection(module, blade, target_blade)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

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


DOCUMENTATION = """
---
module: purefb_fs_replica
version_added: '1.0.0'
short_description:  Manage filesystem replica links between Pure Storage FlashBlades
description:
    - This module manages filesystem replica links between Pure Storage FlashBlades.
author: Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
      - Local Filesystem Name.
    required: true
    type: str
  state:
    description:
      - Creates or modifies a filesystem replica link
    required: false
    default: present
    type: str
    choices: [ "present", "absent" ]
  target_array:
    description:
      - Remote array name to create replica on.
    required: false
    type: str
  target_fs:
    description:
      - Name of target filesystem name
      - If not supplied, will default to I(name).
    type: str
    required: false
  policy:
    description:
      - Name of filesystem snapshot policy to apply to the replica link.
    required: false
    type: str
extends_documentation_fragment:
    - purestorage.flashblade.purestorage.fb
"""

EXAMPLES = """
- name: Create new filesystem replica from foo to bar on arrayB
  purestorage.flashblade.purefb_fs_replica:
    name: foo
    target_array: arrayB
    target_fs: bar
    policy: daily
    state: present
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Add new snapshot policy to exisitng filesystem replica link
  purestorage.flashblade.purefb_fs_replica:
    name: foo
    policy: weekly
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Delete snapshot policy from filesystem replica foo
  purestorage.flashblade.purefb_fs_replica:
    name: foo
    policy: weekly
    state: absent
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641"""

RETURN = """
"""

HAS_PURITY_FB = True
try:
    from purity_fb import FileSystemReplicaLink, LocationReference
except ImportError:
    HAS_PURITY_FB = False

MIN_REQUIRED_API_VERSION = "1.9"

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_blade,
    purefb_argument_spec,
)


def get_local_fs(module, blade):
    """Return Filesystem or None"""
    try:
        res = blade.file_systems.list_file_systems(names=[module.params["name"]])
        return res.items[0]
    except Exception:
        return None


def get_local_rl(module, blade):
    """Return Filesystem Replica Link or None"""
    try:
        res = blade.file_system_replica_links.list_file_system_replica_links(
            local_file_system_names=[module.params["name"]]
        )
        return res.items[0]
    except Exception:
        return None


def _check_connected(module, blade):
    connected_blades = blade.array_connections.list_array_connections()
    for target in range(0, len(connected_blades.items)):
        if (
            connected_blades.items[target].remote.name == module.params["target_array"]
            or connected_blades.items[target].management_address
            == module.params["target_array"]
        ) and connected_blades.items[target].status in [
            "connected",
            "connecting",
            "partially_connected",
        ]:
            return connected_blades.items[target]
    return None


def create_rl(module, blade):
    """Create Filesystem Replica Link"""
    changed = True
    if not module.check_mode:
        try:
            remote_array = _check_connected(module, blade)
            if remote_array:
                if not module.params["target_fs"]:
                    module.params["target_fs"] = module.params["name"]
                if not module.params["policy"]:
                    blade.file_system_replica_links.create_file_system_replica_links(
                        local_file_system_names=[module.params["name"]],
                        remote_file_system_names=[module.params["target_fs"]],
                        remote_names=[remote_array.remote.name],
                    )
                else:
                    blade.file_system_replica_links.create_file_system_replica_links(
                        local_file_system_names=[module.params["name"]],
                        remote_file_system_names=[module.params["target_fs"]],
                        remote_names=[remote_array.remote.name],
                        file_system_replica_link=FileSystemReplicaLink(
                            policies=[LocationReference(name=module.params["policy"])]
                        ),
                    )
            else:
                module.fail_json(
                    msg="Target array {0} is not connected".format(
                        module.params["target_array"]
                    )
                )
        except Exception:
            module.fail_json(
                msg="Failed to create filesystem replica link for {0}.".format(
                    module.params["name"]
                )
            )
    module.exit_json(changed=changed)


def add_rl_policy(module, blade):
    """Add Policy to Filesystem Replica Link"""
    changed = False
    if not module.params["target_array"]:
        module.params["target_array"] = (
            blade.file_system_replica_links.list_file_system_replica_links(
                local_file_system_names=[module.params["name"]]
            )
            .items[0]
            .remote.name
        )
    remote_array = _check_connected(module, blade)
    try:
        already_a_policy = (
            blade.file_system_replica_links.list_file_system_replica_link_policies(
                local_file_system_names=[module.params["name"]],
                policy_names=[module.params["policy"]],
                remote_names=[remote_array.remote.name],
            )
        )
        if not already_a_policy.items:
            changed = True
            if not module.check_mode:
                blade.file_system_replica_links.create_file_system_replica_link_policies(
                    policy_names=[module.params["policy"]],
                    local_file_system_names=[module.params["name"]],
                    remote_names=[remote_array.remote.name],
                )
    except Exception:
        module.fail_json(
            msg="Failed to add policy {0} to replica link {1}.".format(
                module.params["policy"], module.params["name"]
            )
        )
    module.exit_json(changed=changed)


def delete_rl_policy(module, blade):
    """Delete Policy from Filesystem Replica Link"""
    changed = True
    if not module.check_mode:
        current_policy = (
            blade.file_system_replica_links.list_file_system_replica_link_policies(
                local_file_system_names=[module.params["name"]],
                policy_names=[module.params["policy"]],
            )
        )
        if current_policy.items:
            try:
                blade.file_system_replica_links.delete_file_system_replica_link_policies(
                    policy_names=[module.params["policy"]],
                    local_file_system_names=[module.params["name"]],
                    remote_names=[current_policy.items[0].link.remote.name],
                )
            except Exception:
                module.fail_json(
                    msg="Failed to remove policy {0} from replica link {1}.".format(
                        module.params["policy"], module.params["name"]
                    )
                )
        else:
            changed = False
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            target_fs=dict(type="str"),
            target_array=dict(type="str"),
            policy=dict(type="str"),
            state=dict(default="present", choices=["present", "absent"]),
        )
    )

    required_if = [["state", "absent", ["policy"]]]

    module = AnsibleModule(
        argument_spec, required_if=required_if, supports_check_mode=True
    )

    if not HAS_PURITY_FB:
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

    local_fs = get_local_fs(module, blade)
    local_replica_link = get_local_rl(module, blade)

    if not local_fs:
        module.fail_json(
            msg="Selected local filesystem {0} does not exist.".format(
                module.params["name"]
            )
        )

    if module.params["policy"]:
        try:
            policy = blade.policies.list_policies(names=[module.params["policy"]])
        except Exception:
            module.fail_json(
                msg="Selected policy {0} does not exist.".format(
                    module.params["policy"]
                )
            )
    else:
        policy = None
    if state == "present" and not local_replica_link:
        create_rl(module, blade)
    elif state == "present" and local_replica_link and policy:
        add_rl_policy(module, blade)
    elif state == "absent" and policy:
        delete_rl_policy(module, blade)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

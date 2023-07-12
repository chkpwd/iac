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
module: purefb_bucket_replica
version_added: '1.0.0'
short_description:  Manage bucket replica links between Pure Storage FlashBlades
description:
    - This module manages bucket replica links between Pure Storage FlashBlades.
author: Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
      - Local Bucket Name.
    required: true
    type: str
  state:
    description:
      - Creates or modifies a bucket replica link
    required: false
    default: present
    type: str
    choices: [ "present", "absent" ]
  target:
    description:
      - Remote array or target name to create replica on.
    required: false
    type: str
  target_bucket:
    description:
      - Name of target bucket name
      - If not supplied, will default to I(name).
    type: str
    required: false
  paused:
    description:
      - State of the bucket replica link
    type: bool
    default: false
  credential:
    description:
      - Name of remote credential name to use.
    required: false
    type: str
extends_documentation_fragment:
    - purestorage.flashblade.purestorage.fb
"""

EXAMPLES = """
- name: Create new bucket replica from foo to bar on arrayB
  purestorage.flashblade.purefb_bucket_replica:
    name: foo
    target: arrayB
    target_bucket: bar
    credentials: cred_1
    state: present
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Pause exisitng bucket replica link
  purestorage.flashblade.purefb_bucket_replica:
    name: foo
    paused: true
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Delete bucket replica link foo
  purestorage.flashblade.purefb_fs_replica:
    name: foo
    state: absent
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641"""

RETURN = """
"""

HAS_PURITY_FB = True
try:
    from purity_fb import BucketReplicaLink, ObjectStoreRemoteCredentials
except ImportError:
    HAS_PURITY_FB = False

MIN_REQUIRED_API_VERSION = "1.9"

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_blade,
    purefb_argument_spec,
)


def get_local_bucket(module, blade):
    """Return Bucket or None"""
    try:
        res = blade.buckets.list_buckets(names=[module.params["name"]])
        return res.items[0]
    except Exception:
        return None


def get_remote_cred(module, blade, target):
    """Return Remote Credential or None"""
    try:
        res = (
            blade.object_store_remote_credentials.list_object_store_remote_credentials(
                names=[target + "/" + module.params["credential"]]
            )
        )
        return res.items[0]
    except Exception:
        return None


def get_local_rl(module, blade):
    """Return Bucket Replica Link or None"""
    try:
        res = blade.bucket_replica_links.list_bucket_replica_links(
            local_bucket_names=[module.params["name"]]
        )
        return res.items[0]
    except Exception:
        return None


def get_connected(module, blade):
    connected_blades = blade.array_connections.list_array_connections()
    for target in range(0, len(connected_blades.items)):
        if (
            connected_blades.items[target].remote.name == module.params["target"]
            or connected_blades.items[target].management_address
            == module.params["target"]
        ) and connected_blades.items[target].status in [
            "connected",
            "connecting",
            "partially_connected",
        ]:
            return connected_blades.items[target].remote.name
    connected_targets = blade.targets.list_targets()
    for target in range(0, len(connected_targets.items)):
        if connected_targets.items[target].name == module.params[
            "target"
        ] and connected_targets.items[target].status in [
            "connected",
            "connecting",
            "partially_connected",
        ]:
            return connected_targets.items[target].name
    return None


def create_rl(module, blade, remote_cred):
    """Create Bucket Replica Link"""
    changed = True
    if not module.check_mode:
        try:
            if not module.params["target_bucket"]:
                module.params["target_bucket"] = module.params["name"]
            else:
                module.params["target_bucket"] = module.params["target_bucket"].lower()
            blade.bucket_replica_links.create_bucket_replica_links(
                local_bucket_names=[module.params["name"]],
                remote_bucket_names=[module.params["target_bucket"]],
                remote_credentials_names=[remote_cred.name],
                bucket_replica_link=BucketReplicaLink(paused=module.params["paused"]),
            )
        except Exception:
            module.fail_json(
                msg="Failed to create bucket replica link {0}.".format(
                    module.params["name"]
                )
            )
    module.exit_json(changed=changed)


def update_rl_policy(module, blade, local_replica_link):
    """Update Bucket Replica Link"""
    changed = False
    new_cred = local_replica_link.remote.name + "/" + module.params["credential"]
    if (
        local_replica_link.paused != module.params["paused"]
        or local_replica_link.remote_credentials.name != new_cred
    ):
        changed = True
        if not module.check_mode:
            try:
                module.warn("{0}".format(local_replica_link))
                blade.bucket_replica_links.update_bucket_replica_links(
                    local_bucket_names=[module.params["name"]],
                    remote_bucket_names=[local_replica_link.remote_bucket.name],
                    remote_names=[local_replica_link.remote.name],
                    bucket_replica_link=BucketReplicaLink(
                        paused=module.params["paused"],
                        remote_credentials=ObjectStoreRemoteCredentials(name=new_cred),
                    ),
                )
            except Exception:
                module.fail_json(
                    msg="Failed to update bucket replica link {0}.".format(
                        module.params["name"]
                    )
                )
    module.exit_json(changed=changed)


def delete_rl_policy(module, blade, local_replica_link):
    """Delete Bucket Replica Link"""
    changed = True
    if not module.check_mode:
        try:
            blade.bucket_replica_links.delete_bucket_replica_links(
                remote_names=[local_replica_link.remote.name],
                local_bucket_names=[module.params["name"]],
                remote_bucket_names=[local_replica_link.remote_bucket.name],
            )
        except Exception:
            module.fail_json(
                msg="Failed to delete bucket replica link {0}.".format(
                    module.params["name"]
                )
            )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            target=dict(type="str"),
            target_bucket=dict(type="str"),
            paused=dict(type="bool", default=False),
            credential=dict(type="str"),
            state=dict(default="present", choices=["present", "absent"]),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_PURITY_FB:
        module.fail_json(msg="purity_fb sdk is required for this module")

    state = module.params["state"]
    module.params["name"] = module.params["name"].lower()
    blade = get_blade(module)
    versions = blade.api_version.list_versions().versions

    if MIN_REQUIRED_API_VERSION not in versions:
        module.fail_json(
            msg="Minimum FlashBlade REST version required: {0}".format(
                MIN_REQUIRED_API_VERSION
            )
        )

    local_bucket = get_local_bucket(module, blade)
    local_replica_link = get_local_rl(module, blade)
    target = get_connected(module, blade)

    if not target:
        module.fail_json(
            msg="Selected target {0} is not connected.".format(module.params["target"])
        )

    if local_replica_link and not module.params["credential"]:
        module.params["credential"] = local_replica_link.remote_credentials.name.split(
            "/"
        )[1]
    remote_cred = get_remote_cred(module, blade, target)
    if not remote_cred:
        module.fail_json(
            msg="Selected remote credential {0} does not exist for target {1}.".format(
                module.params["credential"], module.params["target"]
            )
        )

    if not local_bucket:
        module.fail_json(
            msg="Selected local bucket {0} does not exist.".format(
                module.params["name"]
            )
        )

    if local_replica_link:
        if local_replica_link.status == "unhealthy":
            module.fail_json(msg="Replica Link unhealthy - please check target")

    if state == "present" and not local_replica_link:
        create_rl(module, blade, remote_cred)
    elif state == "present" and local_replica_link:
        update_rl_policy(module, blade, local_replica_link)
    elif state == "absent" and local_replica_link:
        delete_rl_policy(module, blade, local_replica_link)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

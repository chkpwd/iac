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
module: purefb_remote_cred
version_added: '1.0.0'
short_description: Create, modify and delete FlashBlade object store remote credentials
description:
- Create, modify and delete object store remote credentials
- You must have a correctly configured remote array or target
- This module is B(not) idempotent when updating existing remote credentials
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Define state of remote credential
    default: present
    choices: [ absent, present ]
    type: str
  name:
    description:
    - The name of the credential
    required: true
    type: str
  access_key:
    description:
    - Access Key ID of the S3 target
    type: str
  secret:
    description:
    - Secret Access Key for the S3 or Azure target
    type: str
  target:
    description:
    - Define whether to initialize the S3 bucket
    required: true
    type: str

extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Create remote credential
  purestorage.flashblade.purefb_remote_cred:
    name: cred1
    access_key: "3794fb12c6204e19195f"
    secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    target: target1
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Delete remote credential
  purestorage.flashblade.purefb_remote_cred:
    name: cred1
    target: target1
    state: absent
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

"""

RETURN = r"""
"""

HAS_PURITY_FB = True
try:
    from purity_fb import ObjectStoreRemoteCredentials
except ImportError:
    HAS_PURITY_FB = False


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_blade,
    purefb_argument_spec,
)

MIN_REQUIRED_API_VERSION = "1.9"


def get_connected(module, blade):
    """Return connected device or None"""
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


def get_remote_cred(module, blade):
    """Return Remote Credential or None"""
    try:
        res = (
            blade.object_store_remote_credentials.list_object_store_remote_credentials(
                names=[module.params["target"] + "/" + module.params["name"]]
            )
        )
        return res.items[0]
    except Exception:
        return None


def create_credential(module, blade):
    """Create remote credential"""
    changed = True
    if not module.check_mode:
        remote_cred = module.params["target"] + "/" + module.params["name"]
        remote_credentials = ObjectStoreRemoteCredentials(
            access_key_id=module.params["access_key"],
            secret_access_key=module.params["secret"],
        )
        try:
            blade.object_store_remote_credentials.create_object_store_remote_credentials(
                names=[remote_cred], remote_credentials=remote_credentials
            )
        except Exception:
            module.fail_json(
                msg="Failed to create remote credential {0}".format(remote_cred)
            )
    module.exit_json(changed=changed)


def update_credential(module, blade):
    """Update remote credential"""
    changed = True
    if not module.check_mode:
        remote_cred = module.params["target"] + "/" + module.params["name"]
        new_attr = ObjectStoreRemoteCredentials(
            access_key_id=module.params["access_key"],
            secret_access_key=module.params["secret"],
        )
        try:
            blade.object_store_remote_credentials.update_object_store_remote_credentials(
                names=[remote_cred], remote_credentials=new_attr
            )
        except Exception:
            module.fail_json(
                msg="Failed to update remote credential {0}".format(remote_cred)
            )
    module.exit_json(changed=changed)


def delete_credential(module, blade):
    """Delete remote credential"""
    changed = True
    if not module.check_mode:
        remote_cred = module.params["target"] + "/" + module.params["name"]
        try:
            blade.object_store_remote_credentials.delete_object_store_remote_credentials(
                names=[remote_cred]
            )
        except Exception:
            module.fail_json(
                msg="Failed to delete remote credential {0}.".format(remote_cred)
            )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="present", choices=["present", "absent"]),
            name=dict(type="str", required=True),
            access_key=dict(type="str", no_log=False),
            secret=dict(type="str", no_log=True),
            target=dict(type="str", required=True),
        )
    )

    required_if = [["state", "present", ["access_key", "secret"]]]

    module = AnsibleModule(
        argument_spec, required_if=required_if, supports_check_mode=True
    )

    if not HAS_PURITY_FB:
        module.fail_json(msg="purity_fb sdk is required for this module")

    blade = get_blade(module)
    api_version = blade.api_version.list_versions().versions

    if MIN_REQUIRED_API_VERSION not in api_version:
        module.fail_json(
            msg="FlashBlade REST version not supported. "
            "Minimum version required: {0}".format(MIN_REQUIRED_API_VERSION)
        )

    target = get_connected(module, blade)

    if not target:
        module.fail_json(
            msg="Selected target {0} is not connected.".format(module.params["target"])
        )

    remote_cred = get_remote_cred(module, blade)

    if module.params["state"] == "present" and not remote_cred:
        create_credential(module, blade)
    elif module.params["state"] == "present":
        update_credential(module, blade)
    elif module.params["state"] == "absent" and remote_cred:
        delete_credential(module, blade)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

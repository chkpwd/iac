#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2018, Simon Dodsley (simon@purestorage.com)
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
module: purefa_endpoint
short_description:  Manage VMware protocol-endpoints on Pure Storage FlashArrays
version_added: '1.0.0'
description:
- Create, delete or eradicate the an endpoint on a Pure Storage FlashArray.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - The name of the endpoint.
    type: str
    required: true
  state:
    description:
    - Define whether the endpoint should exist or not.
    default: present
    choices: [ absent, present ]
    type: str
  eradicate:
    description:
    - Define whether to eradicate the endpoint on delete or leave in trash.
    type: bool
    default: false
  rename:
    description:
    - Value to rename the specified endpoint to.
    - Rename only applies to the container the current endpoint is in.
    type: str
  host:
    description:
    - name of host to attach endpoint to
    type: str
  hgroup:
    description:
    - name of hostgroup to attach endpoint to
    type: str
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Create new endpoint named foo
  purestorage.flasharray.purefa_endpoint:
    name: test-endpoint
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: present

- name: Delete and eradicate endpoint named foo
  purestorage.flasharray.purefa_endpoint:
    name: foo
    eradicate: true
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: absent

- name: Rename endpoint foor to bar
  purestorage.flasharray.purefa_endpoint:
    name: foo
    rename: bar
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
volume:
    description: A dictionary describing the changed volume.  Only some
        attributes below will be returned with various actions.
    type: dict
    returned: success
    contains:
        source:
            description: Volume name of source volume used for volume copy
            type: str
        serial:
            description: Volume serial number
            type: str
            sample: '361019ECACE43D83000120A4'
        created:
            description: Volume creation time
            type: str
            sample: '2019-03-13T22:49:24Z'
        name:
            description: Volume name
            type: str
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_system,
    purefa_argument_spec,
)


VGROUPS_API_VERSION = "1.13"


def get_volume(volume, array):
    """Return Volume or None"""
    try:
        return array.get_volume(volume, pending=True)
    except Exception:
        return None


def get_target(volume, array):
    """Return Volume or None"""
    try:
        return array.get_volume(volume, pending=True)
    except Exception:
        return None


def get_endpoint(vol, array):
    """Return Endpoint or None"""
    try:
        return array.get_volume(vol, protocol_endpoint=True)
    except Exception:
        return None


def get_destroyed_endpoint(vol, array):
    """Return Endpoint Endpoint or None"""
    try:
        return bool(
            array.get_volume(vol, protocol_endpoint=True, pending=True)[
                "time_remaining"
            ]
            != ""
        )
    except Exception:
        return None


def check_vgroup(module, array):
    """Check is the requested VG to create volume in exists"""
    vg_exists = False
    vg_name = module.params["name"].split("/")[0]
    try:
        vgs = array.list_vgroups()
    except Exception:
        module.fail_json(msg="Failed to get volume groups list. Check array.")
    for vgroup in range(0, len(vgs)):
        if vg_name == vgs[vgroup]["name"]:
            vg_exists = True
            break
    return vg_exists


def create_endpoint(module, array):
    """Create Endpoint"""
    changed = False
    volfact = []
    if "/" in module.params["name"] and not check_vgroup(module, array):
        module.fail_json(
            msg="Failed to create endpoint {0}. Volume Group does not exist.".format(
                module.params["name"]
            )
        )
    try:
        changed = True
        if not module.check_mode:
            volfact = array.create_conglomerate_volume(module.params["name"])
    except Exception:
        module.fail_json(
            msg="Endpoint {0} creation failed.".format(module.params["name"])
        )
    if module.params["host"]:
        try:
            if not module.check_mode:
                array.connect_host(module.params["host"], module.params["name"])
        except Exception:
            module.fail_json(
                msg="Failed to attach endpoint {0} to host {1}.".format(
                    module.params["name"], module.params["host"]
                )
            )
    if module.params["hgroup"]:
        try:
            if not module.check_mode:
                array.connect_hgroup(module.params["hgroup"], module.params["name"])
        except Exception:
            module.fail_json(
                msg="Failed to attach endpoint {0} to hostgroup {1}.".format(
                    module.params["name"], module.params["hgroup"]
                )
            )

    module.exit_json(changed=changed, volume=volfact)


def rename_endpoint(module, array):
    """Rename endpoint within a container, ie vgroup or local array"""
    changed = False
    volfact = []
    target_name = module.params["rename"]
    if "/" in module.params["rename"] or "::" in module.params["rename"]:
        module.fail_json(msg="Target endpoint cannot include a container name")
    if "/" in module.params["name"]:
        vgroup_name = module.params["name"].split("/")[0]
        target_name = vgroup_name + "/" + module.params["rename"]
    if get_target(target_name, array) or get_destroyed_endpoint(target_name, array):
        module.fail_json(msg="Target endpoint {0} already exists.".format(target_name))
    else:
        try:
            changed = True
            if not module.check_mode:
                volfact = array.rename_volume(module.params["name"], target_name)
        except Exception:
            module.fail_json(
                msg="Rename endpoint {0} to {1} failed.".format(
                    module.params["name"], module.params["rename"]
                )
            )

    module.exit_json(changed=changed, volume=volfact)


def delete_endpoint(module, array):
    """Delete Endpoint"""
    changed = True
    volfact = []
    if not module.check_mode:
        try:
            array.destroy_volume(module.params["name"])
            if module.params["eradicate"]:
                try:
                    volfact = array.eradicate_volume(module.params["name"])
                except Exception:
                    module.fail_json(
                        msg="Eradicate endpoint {0} failed.".format(
                            module.params["name"]
                        )
                    )
        except Exception:
            module.fail_json(
                msg="Delete endpoint {0} failed.".format(module.params["name"])
            )
    module.exit_json(changed=changed, volume=volfact)


def recover_endpoint(module, array):
    """Recover Deleted Endpoint"""
    changed = True
    volfact = []
    if not module.check_mode:
        try:
            array.recover_volume(module.params["name"])
        except Exception:
            module.fail_json(
                msg="Recovery of endpoint {0} failed".format(module.params["name"])
            )
    module.exit_json(changed=changed, volume=volfact)


def eradicate_endpoint(module, array):
    """Eradicate Deleted Endpoint"""
    changed = True
    volfact = []
    if not module.check_mode:
        if module.params["eradicate"]:
            try:
                array.eradicate_volume(module.params["name"], protocol_endpoint=True)
            except Exception:
                module.fail_json(
                    msg="Eradication of endpoint {0} failed".format(
                        module.params["name"]
                    )
                )
    module.exit_json(changed=changed, volume=volfact)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            rename=dict(type="str"),
            host=dict(type="str"),
            hgroup=dict(type="str"),
            eradicate=dict(type="bool", default=False),
            state=dict(type="str", default="present", choices=["absent", "present"]),
        )
    )

    mutually_exclusive = [["rename", "eradicate"], ["host", "hgroup"]]

    module = AnsibleModule(
        argument_spec, mutually_exclusive=mutually_exclusive, supports_check_mode=True
    )

    state = module.params["state"]
    destroyed = False
    array = get_system(module)
    api_version = array._list_available_rest_versions()
    if VGROUPS_API_VERSION not in api_version:
        module.fail_json(
            msg="Purity version does not support endpoints. Please contact support"
        )
    volume = get_volume(module.params["name"], array)
    if volume:
        module.fail_json(
            msg="Volume {0} is an true volume. Please use the purefa_volume module".format(
                module.params["name"]
            )
        )
    endpoint = get_endpoint(module.params["name"], array)
    if not endpoint:
        destroyed = get_destroyed_endpoint(module.params["name"], array)

    if state == "present" and not endpoint and not destroyed:
        create_endpoint(module, array)
    elif state == "present" and endpoint and module.params["rename"]:
        rename_endpoint(module, array)
    elif state == "present" and destroyed:
        recover_endpoint(module, array)
    elif state == "absent" and endpoint:
        delete_endpoint(module, array)
    elif state == "absent" and destroyed:
        eradicate_endpoint(module, array)
    elif state == "absent" and not endpoint and not volume:
        module.exit_json(changed=False)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

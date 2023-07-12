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
module: purefa_pod_replica
short_description:  Manage ActiveDR pod replica links between Pure Storage FlashArrays
version_added: '1.0.0'
description:
    - This module manages ActiveDR pod replica links between Pure Storage FlashArrays.
author: Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
      - ActiveDR source pod name
    required: true
    type: str
  state:
    description:
      - Creates or modifies a pod replica link
    required: false
    default: present
    type: str
    choices: [ "present", "absent" ]
  target_array:
    description:
      - Remote array name to create replica on.
    required: false
    type: str
  target_pod:
    description:
      - Name of target pod
      - Must not be the same as the local pod.
    type: str
    required: false
  pause:
    description:
      - Pause/unpause a pod replica link
    required: false
    type: bool
extends_documentation_fragment:
    - purestorage.flasharray.purestorage.fa
"""

EXAMPLES = """
- name: Create new pod replica link from foo to bar on arrayB
  purestorage.flasharray.purefa_pod_replica:
    name: foo
    target_array: arrayB
    target_pod: bar
    state: present
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Pause an pod replica link
  purestorage.flasharray.purefa_pod_replica:
    name: foo
    pause: true
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Delete and eradicate pod replica link
  purestorage.flasharray.purefa_pod_replica:
    name: foo
    state: absent
    eradicate: true
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = """
"""

MIN_REQUIRED_API_VERSION = "1.19"

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_system,
    purefa_argument_spec,
)


def get_local_pod(module, array):
    """Return Pod or None"""
    try:
        return array.get_pod(module.params["name"])
    except Exception:
        return None


def get_local_rl(module, array):
    """Return Pod Replica Link or None"""
    try:
        rlinks = array.list_pod_replica_links()
        for link in range(0, len(rlinks)):
            if rlinks[link]["local_pod_name"] == module.params["name"]:
                return rlinks[link]
        return None
    except Exception:
        return None


def _get_arrays(array):
    """Get Connected Arrays"""
    arrays = []
    array_details = array.list_array_connections()
    for arraycnt in range(0, len(array_details)):
        arrays.append(array_details[arraycnt]["array_name"])
    return arrays


def update_rl(module, array, local_rl):
    """Create Pod Replica Link"""
    changed = False
    if module.params["pause"] is not None:
        if local_rl["status"] != "paused" and module.params["pause"]:
            changed = True
            if not module.check_mode:
                try:
                    array.pause_pod_replica_link(
                        local_pod_name=module.params["name"],
                        remote_pod_name=local_rl["remote_pod_name"],
                    )
                except Exception:
                    module.fail_json(
                        msg="Failed to pause replica link {0}.".format(
                            module.params["name"]
                        )
                    )
        elif local_rl["status"] == "paused" and not module.params["pause"]:
            changed = True
            if not module.check_mode:
                try:
                    array.resume_pod_replica_link(
                        local_pod_name=module.params["name"],
                        remote_pod_name=local_rl["remote_pod_name"],
                    )
                except Exception:
                    module.fail_json(
                        msg="Failed to resume replica link {0}.".format(
                            module.params["name"]
                        )
                    )
    module.exit_json(changed=changed)


def create_rl(module, array):
    """Create Pod Replica Link"""
    changed = True
    if not module.params["target_pod"]:
        module.fail_json(msg="target_pod required to create a new replica link.")
    if not module.params["target_array"]:
        module.fail_json(msg="target_array required to create a new replica link.")
    try:
        connected_arrays = array.list_array_connections()
        if connected_arrays == []:
            module.fail_json(msg="No connected arrays.")
        else:
            good_array = False
            for conn_array in range(0, len(connected_arrays)):
                if connected_arrays[conn_array]["array_name"] == module.params[
                    "target_array"
                ] and connected_arrays[conn_array]["status"] in [
                    "connected",
                    "connecting",
                    "partially_connected",
                ]:
                    good_array = True
                    break
            if not good_array:
                module.fail_json(
                    msg="Target array {0} is not connected to the source array.".format(
                        module.params["target_array"]
                    )
                )
            else:
                if not module.check_mode:
                    try:
                        array.create_pod_replica_link(
                            local_pod_name=module.params["name"],
                            remote_name=module.params["target_array"],
                            remote_pod_name=module.params["target_pod"],
                        )
                    except Exception:
                        module.fail_json(
                            msg="Failed to create replica link {0} to target array {1}".format(
                                module.params["name"], module.params["target_array"]
                            )
                        )
    except Exception:
        module.fail_json(
            msg="Failed to create replica link for pod {0}.".format(
                module.params["name"]
            )
        )
    module.exit_json(changed=changed)


def delete_rl(module, array, local_rl):
    """Delete Pod Replica Link"""
    changed = True
    if not module.check_mode:
        try:
            array.delete_pod_replica_link(
                module.params["name"], remote_pod_name=local_rl["remote_pod_name"]
            )
        except Exception:
            module.fail_json(
                msg="Failed to delete replica link for pod {0}.".format(
                    module.params["name"]
                )
            )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            target_pod=dict(type="str"),
            target_array=dict(type="str"),
            pause=dict(type="bool"),
            state=dict(default="present", choices=["present", "absent"]),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    state = module.params["state"]
    array = get_system(module)
    api_version = array._list_available_rest_versions()

    if MIN_REQUIRED_API_VERSION not in api_version:
        module.fail_json(msg="Purity v6.0.0 or higher required.")

    local_pod = get_local_pod(module, array)
    local_replica_link = get_local_rl(module, array)

    if not local_pod:
        module.fail_json(
            msg="Selected local pod {0} does not exist.".format(module.params["name"])
        )

    if len(local_pod["arrays"]) > 1:
        module.fail_json(
            msg="Local Pod {0} is already stretched.".format(module.params["name"])
        )

    if local_replica_link:
        if local_replica_link["status"] == "unhealthy":
            module.fail_json(msg="Replca Link unhealthy - please check remote array")
    if state == "present" and not local_replica_link:
        create_rl(module, array)
    elif state == "present" and local_replica_link:
        update_rl(module, array, local_replica_link)
    elif state == "absent" and local_replica_link:
        delete_rl(module, array, local_replica_link)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

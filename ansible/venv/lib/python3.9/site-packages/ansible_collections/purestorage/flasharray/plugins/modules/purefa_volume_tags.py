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
module: purefa_volume_tags
version_added: '1.0.0'
short_description:  Manage volume tags on Pure Storage FlashArrays
description:
- Manage volume tags for volumes on Pure Storage FlashArray.
- Requires a minimum of Purity 6.0.0
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - The name of the volume.
    type: str
    required: true
  namespace:
    description:
    - The name of tag namespace
    default: default
    type: str
  copyable:
    description:
    - Define whether the volume tags are inherited on volume copies.
    default: true
    type: bool
  kvp:
    description:
    - List of key value pairs to assign to the volume.
    - Seperate the key from the value using a colon (:) only.
    - All items in list will use I(namespace) and I(copyable) settings.
    - Maximum of 5 tags per volume
    - See examples for exact formatting requirements
    type: list
    elements: str
    required: true
  state:
    description:
    - Define whether the volume tag(s) should exist or not.
    default: present
    choices: [ absent, present ]
    type: str
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Create new tags in namespace test for volume foo
  purestorage.flasharray.purefa_volume_tags:
    name: foo
    namespace: test
    copyable: false
    kvp:
    - 'key1:value1'
    - 'key2:value2'
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Remove an existing tag in namespace test for volume foo
  purestorage.flasharray.purefa_volume_tags:
    name: foo
    namespace: test
    kvp:
    - 'key1:value1'
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: absent

- name: Update an existing tag in namespace test for volume foo
  purestorage.flasharray.purefa_volume_tags:
    name: foo
    namespace: test
    kvp:
    - 'key1:value2'
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: present
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_system,
    purefa_argument_spec,
)


TAGS_API_VERSION = "1.19"


def get_volume(module, array):
    """Return Volume or None"""
    try:
        return array.get_volume(module.params["name"], pending=True)
    except Exception:
        return None


def get_endpoint(name, array):
    """Return Endpoint or None"""
    try:
        return array.get_volume(name, pending=True, protocol_endpoint=True)
    except Exception:
        return None


def create_tag(module, array):
    """Create Volume Tag"""
    changed = True
    if not module.check_mode:
        for tag in range(0, len(module.params["kvp"])):
            try:
                array.add_tag_to_volume(
                    module.params["name"],
                    copyable=module.params["copyable"],
                    namespace=module.params["namespace"],
                    key=module.params["kvp"][tag].split(":")[0],
                    value=module.params["kvp"][tag].split(":")[1],
                )
            except Exception:
                module.fail_json(
                    msg="Failed to add tag KVP {0} to volume {1}".format(
                        module.params["kvp"][tag], module.params["name"]
                    )
                )

    module.exit_json(changed=changed)


def update_tag(module, array, current_tags):
    """Update Volume Tag"""
    changed = False
    for tag in range(0, len(module.params["kvp"])):
        tag_exists = False
        for current_tag in range(0, len(current_tags)):
            if (
                module.params["kvp"][tag].split(":")[0]
                == current_tags[current_tag]["key"]
                and module.params["namespace"] == current_tags[current_tag]["namespace"]
            ):
                tag_exists = True
                if (
                    module.params["kvp"][tag].split(":")[1]
                    != current_tags[current_tag]["value"]
                ):
                    changed = True
                    if not module.check_mode:
                        try:
                            array.add_tag_to_volume(
                                module.params["name"],
                                namespace=module.params["namespace"],
                                key=module.params["kvp"][tag].split(":")[0],
                                value=module.params["kvp"][tag].split(":")[1],
                            )
                        except Exception:
                            module.fail_json(
                                msg="Failed to update tag '{0}' from volume {1}".format(
                                    module.params["kvp"][tag].split(":")[0],
                                    module.params["name"],
                                )
                            )

        if not tag_exists:
            changed = True
            if not module.check_mode:
                try:
                    array.add_tag_to_volume(
                        module.params["name"],
                        namespace=module.params["namespace"],
                        key=module.params["kvp"][tag].split(":")[0],
                        value=module.params["kvp"][tag].split(":")[1],
                    )
                except Exception:
                    module.fail_json(
                        msg="Failed to add tag KVP {0} to volume {1}".format(
                            module.params["kvp"][tag].split(":")[0],
                            module.params["name"],
                        )
                    )
    module.exit_json(changed=changed)


def delete_tag(module, array, current_tags):
    """Delete Tag"""
    changed = False
    for tag in range(0, len(module.params["kvp"])):
        for current_tag in range(0, len(current_tags)):
            if (
                module.params["kvp"][tag].split(":")[0]
                == current_tags[current_tag]["key"]
                and module.params["namespace"] == current_tags[current_tag]["namespace"]
            ):
                changed = True
                if not module.check_mode:
                    try:
                        array.remove_tag_from_volume(
                            module.params["name"],
                            namespace=module.params["namespace"],
                            key=module.params["kvp"][tag].split(":")[0],
                        )
                    except Exception:
                        module.fail_json(
                            msg="Failed to remove tag KVP '{0}' from volume {1}".format(
                                module.params["kvp"][tag], module.params["name"]
                            )
                        )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            copyable=dict(type="bool", default=True),
            namespace=dict(type="str", default="default"),
            state=dict(type="str", default="present", choices=["absent", "present"]),
            kvp=dict(type="list", elements="str", required=True),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    state = module.params["state"]
    if module.params["kvp"] is not None:
        module.params["kvp"] = sorted(module.params["kvp"][0:5])
    else:
        module.fail_json(msg="No KVPs specified. Minimum of 1 is required.")
    array = get_system(module)
    api_version = array._list_available_rest_versions()

    if TAGS_API_VERSION not in api_version:
        module.fail_json(
            msg="Volume tags are not supported. Purity 6.0.0, or higher, is required."
        )

    volume = get_volume(module, array)
    endpoint = get_endpoint(module.params["name"], array)

    if not volume:
        module.fail_json(msg="Volume {0} does not exist.".format(module.params["name"]))
    if endpoint:
        module.fail_json(
            msg="Volume {0} is an endpoint. Tags not allowed.".format(
                module.params["name"]
            )
        )
    if "." in module.params["name"]:
        current_tags = array.get_volume(
            module.params["name"],
            snap=True,
            pending=True,
            tags=True,
            namespace=module.params["namespace"],
        )
    else:
        current_tags = array.get_volume(
            module.params["name"],
            pending=True,
            tags=True,
            namespace=module.params["namespace"],
        )

    if state == "present" and not current_tags:
        create_tag(module, array)
    elif state == "absent" and not current_tags:
        module.exit_json(changed=False)
    elif state == "present" and current_tags:
        update_tag(module, array, current_tags)
    elif state == "absent" and current_tags:
        delete_tag(module, array, current_tags)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

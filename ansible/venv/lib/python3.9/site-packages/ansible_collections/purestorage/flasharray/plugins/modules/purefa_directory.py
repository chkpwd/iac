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
module: purefa_directory
version_added: '1.5.0'
short_description: Manage FlashArray File System Directories
description:
- Create/Delete FlashArray File Systems
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - Name of the directory
    type: str
    required: true
  state:
    description:
    - Define whether the directory should exist or not.
    default: present
    choices: [ absent, present ]
    type: str
  filesystem:
    description:
    - Name of the filesystem the directory links to.
    type: str
    required: true
  path:
    description:
    - Path of the managed directory in the file system
    - If not provided will default to I(name)
    type: str
  rename:
    description:
    - Value to rename the specified directory to
    type: str
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Create direcotry foo in filesysten bar with path zeta
  purestorage.flasharray.purefa_directory:
    name: foo
    filesystem: bar
    path: zeta
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Rename directory foo to fin in filesystem bar
  purestorage.flasharray.purefa_directory:
    name: foo
    rename: fin
    filesystem: bar
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Delete diectory foo in filesystem bar
  purestorage.flasharray.purefa_directory:
    name: foo
    filesystem: bar
    state: absent
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""

HAS_PURESTORAGE = True
try:
    from pypureclient import flasharray
except ImportError:
    HAS_PURESTORAGE = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_system,
    get_array,
    purefa_argument_spec,
)

MIN_REQUIRED_API_VERSION = "2.2"


def delete_dir(module, array):
    """Delete a file system directory"""
    changed = True
    if not module.check_mode:
        res = array.delete_directories(
            names=[module.params["filesystem"] + ":" + module.params["name"]]
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to delete file system {0}. {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def rename_dir(module, array):
    """Rename a file system directory"""
    changed = False
    target = array.get_directories(
        names=[module.params["filesystem"] + ":" + module.params["rename"]]
    )
    if target.status_code != 200:
        if not module.check_mode:
            changed = True
            directory = flasharray.DirectoryPatch(
                name=module.params["filesystem"] + ":" + module.params["rename"]
            )
            res = array.patch_directories(
                names=[module.params["filesystem"] + ":" + module.params["name"]],
                directory=directory,
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to delete file system {0}".format(module.params["name"])
                )
    else:
        module.fail_json(
            msg="Target file system {0} already exists".format(module.params["rename"])
        )
    module.exit_json(changed=changed)


def create_dir(module, array):
    """Create a file system directory"""
    changed = False
    if not module.params["path"]:
        module.params["path"] = module.params["name"]
    all_fs = list(
        array.get_directories(file_system_names=[module.params["filesystem"]]).items
    )
    for check in range(0, len(all_fs)):
        if module.params["path"] == all_fs[check].path[1:]:
            module.fail_json(
                msg="Path {0} already existis in file system {1}".format(
                    module.params["path"], module.params["filesystem"]
                )
            )
    changed = True
    if not module.check_mode:
        directory = flasharray.DirectoryPost(
            directory_name=module.params["name"], path=module.params["path"]
        )
        res = array.post_directories(
            file_system_names=[module.params["filesystem"]], directory=directory
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to create file system {0}. {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="present", choices=["absent", "present"]),
            filesystem=dict(type="str", required=True),
            name=dict(type="str", required=True),
            rename=dict(type="str"),
            path=dict(type="str"),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    array = get_system(module)
    api_version = array._list_available_rest_versions()
    if MIN_REQUIRED_API_VERSION not in api_version:
        module.fail_json(
            msg="FlashArray REST version not supported. "
            "Minimum version required: {0}".format(MIN_REQUIRED_API_VERSION)
        )
    array = get_array(module)
    state = module.params["state"]

    try:
        filesystem = list(
            array.get_file_systems(names=[module.params["filesystem"]]).items
        )[0]
    except Exception:
        module.fail_json(
            msg="Selected file system {0} does not exist".format(
                module.params["filesystem"]
            )
        )
    res = array.get_directories(
        names=[module.params["filesystem"] + ":" + module.params["name"]]
    )
    exists = bool(res.status_code == 200)

    if state == "present" and not exists:
        create_dir(module, array)
    elif (
        state == "present"
        and exists
        and module.params["rename"]
        and not filesystem.destroyed
    ):
        rename_dir(module, array)
    elif state == "absent" and exists:
        delete_dir(module, array)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

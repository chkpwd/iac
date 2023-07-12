#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2021, Simon Dodsley (simon@purestorage.com)
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
module: purefb_virtualhost
version_added: '1.6.0'
short_description: Manage FlashBlade Object Store Virtual Hosts
description:
- Add or delete FlashBlade Object Store Virtual Hosts
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - Name of the Object Store Virtual Host
    - A hostname or domain by which the array can be addressed for virtual
      hosted-style S3 requests.
    type: str
    required: true
  state:
    description:
    - Define whether the Object Store Virtual Host should be added or deleted
    default: present
    choices: [ absent, present ]
    type: str
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Add Object Store Virtual Host
  purestorage.flashblade.purefb_virtualhost:
    name: "s3.acme.com"
    fb_url: 10.10.10.2
    api_token: T-68618f31-0c9e-4e57-aa44-5306a2cf10e3

- name: Delete Object Store Virtual Host
  purestorage.flashblade.purefb_virtualhost:
    name: "nohost.acme.com"
    state: absent
    fb_url: 10.10.10.2
    api_token: T-68618f31-0c9e-4e57-aa44-5306a2cf10e3
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)

MIN_REQUIRED_API_VERSION = "2.0"
MAX_HOST_COUNT = 10


def delete_host(module, blade):
    """Delete Object Store Virtual Host"""
    changed = False
    if module.params["name"] == "s3.amazonaws.com":
        module.warn("s3.amazonaws.com is a reserved name and cannot be deleted")
    else:
        changed = True
        if not module.check_mode:
            res = blade.delete_object_store_virtual_hosts(names=[module.params["name"]])
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to delete Object Store Virtual Host {0}".format(
                        module.params["name"]
                    )
                )
    module.exit_json(changed=changed)


def add_host(module, blade):
    """Add Object Store Virtual Host"""
    changed = True
    if not module.check_mode:
        res = blade.post_object_store_virtual_hosts(names=[module.params["name"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to add Object Store Virtual Host {0}".format(
                    module.params["name"]
                )
            )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="present", choices=["absent", "present"]),
            name=dict(type="str", required=True),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    blade = get_system(module)
    api_version = list(blade.get_versions().items)

    if MIN_REQUIRED_API_VERSION not in api_version:
        module.fail_json(
            msg="FlashBlade REST version not supported. "
            "Minimum version required: {0}".format(MIN_REQUIRED_API_VERSION)
        )
    state = module.params["state"]

    exists = bool(
        blade.get_object_store_virtual_hosts(names=[module.params["name"]]).status_code
        == 200
    )

    if len(list(blade.get_object_store_virtual_hosts().items)) < MAX_HOST_COUNT:
        if not exists and state == "present":
            add_host(module, blade)
        elif exists and state == "absent":
            delete_host(module, blade)
    else:
        module.warn("Maximum Object Store Virtual Host reached.")

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

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
module: purefa_console
version_added: '1.0.0'
short_description: Enable or Disable Pure Storage FlashArray Console Lock
description:
- Enablke or Disable root lockout from the array at the physical console for a Pure Storage FlashArray.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Define state of console lockout
    - When set to I(enable) the console port is locked from root login.
    type: str
    default: disable
    choices: [ enable, disable ]
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Enable Console Lockout
  purestorage.flasharray.purefa_console:
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Disable Console Lockout
  purestorage.flasharray.purefa_console:
    state: disable
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_system,
    purefa_argument_spec,
)


def enable_console(module, array):
    """Enable Console Lockout"""
    changed = False
    if array.get_console_lock_status()["console_lock"] != "enabled":
        changed = True
        if not module.check_mode:
            try:
                array.enable_console_lock()
            except Exception:
                module.fail_json(msg="Enabling Console Lock failed")
    module.exit_json(changed=changed)


def disable_console(module, array):
    """Disable Console Lock"""
    changed = False
    if array.get_console_lock_status()["console_lock"] == "enabled":
        changed = True
        if not module.check_mode:
            try:
                array.disable_console_lock()
            except Exception:
                module.fail_json(msg="Disabling Console Lock failed")
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="disable", choices=["enable", "disable"]),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    array = get_system(module)

    if module.params["state"] == "enable":
        enable_console(module, array)
    else:
        disable_console(module, array)
    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

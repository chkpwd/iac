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
module: purefa_timeout
version_added: '1.0.0'
short_description: Configure Pure Storage FlashArray GUI idle timeout
description:
- Configure GUI idle timeout for Pure Storage FlashArrays.
- This does not affect existing GUI sessions.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Set or disable the GUI idle timeout
    default: present
    type: str
    choices: [ present, absent ]
  timeout:
    description:
    - Minutes for idle timeout.
    type: int
    default: 30
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Set GUI idle timeout to 25 minutes
  purestorage.flasharray.purefa_timeout:
    timeout: 25
    state: present
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Disable idle timeout
  purestorage.flasharray.purefa_timeout:
    state: absent
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


def set_timeout(module, array):
    """Set GUI idle timeout"""
    changed = True
    if not module.check_mode:
        try:
            array.set(idle_timeout=module.params["timeout"])
        except Exception:
            module.fail_json(msg="Failed to set GUI idle timeout")

    module.exit_json(changed=changed)


def disable_timeout(module, array):
    """Disable idle timeout"""
    changed = True
    if not module.check_mode:
        try:
            array.set(idle_timeout=0)
        except Exception:
            module.fail_json(msg="Failed to disable GUI idle timeout")
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            timeout=dict(type="int", default=30),
            state=dict(type="str", default="present", choices=["present", "absent"]),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    state = module.params["state"]
    if 5 < module.params["timeout"] > 180 and module.params["timeout"] != 0:
        module.fail_json(msg="Timeout value must be between 5 and 180 minutes")
    array = get_system(module)
    current_timeout = array.get(idle_timeout=True)["idle_timeout"]
    if state == "present" and current_timeout != module.params["timeout"]:
        set_timeout(module, array)
    elif state == "absent" and current_timeout != 0:
        disable_timeout(module, array)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

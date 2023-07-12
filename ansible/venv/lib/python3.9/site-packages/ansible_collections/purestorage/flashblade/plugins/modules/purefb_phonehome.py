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
module: purefb_phonehome
version_added: '1.0.0'
short_description: Enable or Disable Pure Storage FlashBlade Phone Home
description:
- Enablke or Disable Remote Phone Home for a Pure Storage FlashBlade.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Define state of phone home
    type: str
    default: present
    choices: [ present, absent ]
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Enable Remote Phone Home
  purestorage.flashblade.purefb_phonehome:
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Disable Remote Phone Home
  purestorage.flashblade.purefb_phonehome:
    state: absent
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
"""

RETURN = r"""
"""

HAS_PURITY_FB = True
try:
    from purity_fb import Support
except ImportError:
    HAS_PURITY_FB = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_blade,
    purefb_argument_spec,
)


MIN_REQUIRED_API_VERSION = "1.6"


def enable_ph(module, blade):
    """Enable Phone Hone"""
    changed = True
    if not module.check_mode:
        ph_settings = Support(phonehome_enabled=True)
        try:
            blade.support.update_support(support=ph_settings)
        except Exception:
            module.fail_json(msg="Enabling Phone Home failed")
    module.exit_json(changed=changed)


def disable_ph(module, blade):
    """Disable Phone Home"""
    changed = True
    if not module.check_mode:
        ph_settings = Support(phonehome_enabled=False)
        try:
            blade.support.update_support(support=ph_settings)
        except Exception:
            module.fail_json(msg="Disabling Phone Home failed")
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="present", choices=["present", "absent"]),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    blade = get_blade(module)
    api_version = blade.api_version.list_versions().versions
    if MIN_REQUIRED_API_VERSION not in api_version:
        module.fail_json(msg="Purity//FB must be upgraded to support this module.")

    if not HAS_PURITY_FB:
        module.fail_json(msg="purity_fb SDK is required for this module")

    if (
        module.params["state"] == "present"
        and not blade.support.list_support().items[0].phonehome_enabled
    ):
        enable_ph(module, blade)
    elif (
        module.params["state"] == "absent"
        and blade.support.list_support().items[0].phonehome_enabled
    ):
        disable_ph(module, blade)
    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

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
module: purefb_eula
version_added: '1.6.0'
short_description: Sign Pure Storage FlashBlade EULA
description:
- Sign the FlashBlade EULA for Day 0 config, or change signatory.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  company:
    description:
    - Full legal name of the entity.
    - The value must be between 1 and 64 characters in length.
    type: str
    required: true
  name:
    description:
    - Full legal name of the individual at the company who has the authority to accept the terms of the agreement.
    - The value must be between 1 and 64 characters in length.
    type: str
    required: true
  title:
    description:
    - Individual's job title at the company.
    - The value must be between 1 and 64 characters in length.
    type: str
    required: true
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Sign EULA for FlashBlade
  purestorage.flashblade.purefb_eula:
    company: "ACME Storage, Inc."
    name: "Fred Bloggs"
    title: "Storage Manager"
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""

HAS_PURITY_FB = True
try:
    from purity_fb import Eula, EulaSignature
except ImportError:
    HAS_PURITY_FB = False


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    get_blade,
    purefb_argument_spec,
)


EULA_API_VERSION = "2.0"


def set_eula(module, blade):
    """Sign EULA"""
    changed = False
    if not module.check_mode:
        current_eula = list(blade.get_arrays_eula().items)[0].signature
        if not current_eula.accepted:
            if (
                current_eula.company != module.params["company"]
                or current_eula.title != module.params["title"]
                or current_eula.name != module.params["name"]
            ):
                signature = EulaSignature(
                    company=module.params["company"],
                    title=module.params["title"],
                    name=module.params["name"],
                )
                eula_body = Eula(signature=signature)
                if not module.check_mode:
                    changed = True
                    rc = blade.patch_arrays_eula(eula=eula_body)
                    if rc.status_code != 200:
                        module.fail_json(msg="Signing EULA failed")
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            company=dict(type="str", required=True),
            name=dict(type="str", required=True),
            title=dict(type="str", required=True),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_PURITY_FB:
        module.fail_json(msg="purity_fb sdk is required for this module")

    blade = get_blade(module)
    api_version = blade.api_version.list_versions().versions
    api_version = blade.api_version.list_versions().versions
    if EULA_API_VERSION not in api_version:
        module.fail_json(msg="Purity//FB must be upgraded to support this module.")
    blade = get_system(module)
    set_eula(module, blade)
    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

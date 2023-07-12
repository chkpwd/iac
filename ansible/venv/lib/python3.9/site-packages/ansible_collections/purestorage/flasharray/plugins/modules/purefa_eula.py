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
module: purefa_eula
version_added: '1.0.0'
short_description: Sign Pure Storage FlashArray EULA
description:
- Sign the FlashArray EULA for Day 0 config, or change signatory.
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
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Sign EULA for FlashArray
  purestorage.flasharray.purefa_eula:
    company: "ACME Storage, Inc."
    name: "Fred Bloggs"
    title: "Storage Manager"
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


EULA_API_VERSION = "1.17"


def set_eula(module, array):
    """Sign EULA"""
    changed = False
    try:
        current_eula = array.get_eula()
    except Exception:
        module.fail_json(msg="Failed to get current EULA")
    if (
        current_eula["acceptance"]["company"] != module.params["company"]
        or current_eula["acceptance"]["title"] != module.params["title"]
        or current_eula["acceptance"]["name"] != module.params["name"]
    ):
        try:
            changed = True
            if not module.check_mode:
                array.set_eula(
                    company=module.params["company"],
                    title=module.params["title"],
                    name=module.params["name"],
                )
        except Exception:
            module.fail_json(msg="Signing EULA failed")
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            company=dict(type="str", required=True),
            name=dict(type="str", required=True),
            title=dict(type="str", required=True),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    array = get_system(module)
    api_version = array._list_available_rest_versions()
    if EULA_API_VERSION in api_version:
        set_eula(module, array)
    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

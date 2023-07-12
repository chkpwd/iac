#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: fusion_hw
version_added: '1.0.0'
deprecated:
    removed_at_date: "2023-08-09"
    why: Hardware type cannot be modified in Pure Storage Fusion
    alternative: there's no alternative as this functionality has never worked before
short_description:  Create hardware types in Pure Storage Fusion
description:
- Create a hardware type in Pure Storage Fusion.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
notes:
- Supports C(check mode).
options:
  name:
    description:
    - The name of the hardware type.
    type: str
  state:
    description:
    - Define whether the hardware type should exist or not.
    - Currently there is no mechanism to delete a hardware type.
    default: present
    choices: [ present ]
    type: str
  display_name:
    description:
    - The human name of the hardware type.
    - If not provided, defaults to I(name).
    type: str
  media_type:
    description:
    - Volume size limit in M, G, T or P units.
    type: str
  array_type:
    description:
    - The array type for the hardware type.
    choices: [ FA//X, FA//C ]
    type: str
extends_documentation_fragment:
- purestorage.fusion.purestorage.fusion
"""

# this module does nothing, thus no example is provided
EXAMPLES = r"""
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.fusion.plugins.module_utils.fusion import (
    fusion_argument_spec,
)


def main():
    """Main code"""
    argument_spec = fusion_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str"),
            display_name=dict(type="str"),
            array_type=dict(type="str", choices=["FA//X", "FA//C"]),
            media_type=dict(type="str"),
            state=dict(type="str", default="present", choices=["present"]),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

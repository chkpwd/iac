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
module: purefa_eradication
version_added: '1.9.0'
short_description: Configure Pure Storage FlashArray Eradication Timer
description:
- Configure the eradication timer for destroyed items on a FlashArray.
- Valid values are integer days from 1 to 30. Default is 1.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  timer:
    description:
    - Set the eradication timer for the FlashArray
    - Allowed values are integers from 1 to 30. Default is 1
    default: 1
    type: int
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Set eradication timer to 30 days
  purestorage.flasharray.purefa_eradication:
    timer: 30
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Set eradication timer to 1 day
  purestorage.flasharray.purefa_eradication:
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""

HAS_PURESTORAGE = True
try:
    from pypureclient.flasharray import Arrays, EradicationConfig
except ImportError:
    HAS_PURESTORAGE = False


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_system,
    get_array,
    purefa_argument_spec,
)

SEC_PER_DAY = 86400000
ERADICATION_API_VERSION = "2.6"


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            timer=dict(type="int", default="1"),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)
    if not 30 >= module.params["timer"] >= 1:
        module.fail_json(msg="Eradication Timer must be between 1 and 30 days.")
    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    array = get_system(module)
    api_version = array._list_available_rest_versions()
    changed = False
    if ERADICATION_API_VERSION in api_version:
        array = get_array(module)
        current_timer = (
            list(array.get_arrays().items)[0].eradication_config.eradication_delay
            / SEC_PER_DAY
        )
        if module.params["timer"] != current_timer:
            changed = True
            if not module.check_mode:
                new_timer = SEC_PER_DAY * module.params["timer"]
                eradication_config = EradicationConfig(eradication_delay=new_timer)
                res = array.patch_arrays(
                    array=Arrays(eradication_config=eradication_config)
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to change Eradication Timer. Error: {0}".format(
                            res.errors[0].message
                        )
                    )
    else:
        module.fail_json(
            msg="Purity version does not support changing Eradication Timer"
        )
    module.exit_json(changed=changed)


if __name__ == "__main__":
    main()

#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2019, Simon Dodsley (simon@purestorage.com)
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
module: purefb_proxy
version_added: '1.0.0'
author:
  - Pure Storage ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
short_description: Configure FlashBlade phonehome HTTPs proxy settings
description:
- Set or erase configuration for the phonehome proxy settings.
options:
  state:
    description:
    - Set or delete proxy configuration
    default: present
    type: str
    choices: [ absent, present ]
  host:
    description:
    - The proxy host name.
    type: str
  port:
    description:
    - The proxy TCP/IP port number.
    type: int
  secure:
    description:
    - Use http or https as the proxy protocol.
    - True uses https, false uses http.
    default: true
    type: bool
    version_added: '1.11.0'
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Delete exisitng proxy settings
  purestorage.flashblade.purefb_proxy:
    state: absent
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Set proxy settings
  purestorage.flashblade.purefb_proxy:
    host: purestorage.com
    port: 8080
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
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


def delete_proxy(module, blade):
    """Delete proxy settings"""
    changed = False
    current_proxy = blade.support.list_support().items[0].proxy
    if current_proxy != "":
        changed = True
        if not module.check_mode:
            try:
                proxy_settings = Support(proxy="")
                blade.support.update_support(support=proxy_settings)
            except Exception:
                module.fail_json(msg="Delete proxy settigs failed")
    module.exit_json(changed=changed)


def create_proxy(module, blade):
    """Set proxy settings"""
    changed = False
    current_proxy = blade.support.list_support().items[0].proxy
    if module.params["secure"]:
        protocol = "https://"
    else:
        protocol = "http://"
    if current_proxy is not None:
        changed = True
        if not module.check_mode:
            new_proxy = (
                protocol + module.params["host"] + ":" + str(module.params["port"])
            )
            if new_proxy != current_proxy:
                try:
                    proxy_settings = Support(proxy=new_proxy)
                    blade.support.update_support(support=proxy_settings)
                except Exception:
                    module.fail_json(msg="Set phone home proxy failed.")

    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="present", choices=["absent", "present"]),
            secure=dict(type="bool", default=True),
            host=dict(type="str"),
            port=dict(type="int"),
        )
    )

    required_together = [["host", "port"]]

    module = AnsibleModule(
        argument_spec, required_together=required_together, supports_check_mode=True
    )

    if not HAS_PURITY_FB:
        module.fail_json(msg="purity_fb SDK is required for this module")

    state = module.params["state"]
    blade = get_blade(module)

    if state == "absent":
        delete_proxy(module, blade)
    elif state == "present":
        create_proxy(module, blade)
    else:
        module.exit_json(changed=False)


if __name__ == "__main__":
    main()

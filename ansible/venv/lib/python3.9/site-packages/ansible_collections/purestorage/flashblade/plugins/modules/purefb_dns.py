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
module: purefb_dns
version_added: '1.0.0'
short_description: Configure Pure Storage FlashBlade DNS settings
description:
- Set or erase DNS configuration for Pure Storage FlashBlades.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Create or delete DNS servers configuration
    type: str
    default: present
    choices: [ absent, present ]
  domain:
    description:
    - Domain suffix to be appended when perofrming DNS lookups.
    type: str
  nameservers:
    description:
    - List of up to 3 unique DNS server IP addresses. These can be
      IPv4 or IPv6 - No validation is done of the addresses is performed.
    type: list
    elements: str
  search:
    description:
    - Ordered list of domain names to search
    - Deprecated option. Will be removed in Collection v1.6.0, There is no replacement for this.
    type: list
    elements: str
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Delete exisitng DNS settings
  purestorage.flashblade.purefb_dns:
    state: absent
    fa_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6

- name: Set DNS settings
  purestorage.flashblade.purefb_dns:
    domain: purestorage.com
    nameservers:
      - 8.8.8.8
      - 8.8.4.4
    search:
      - purestorage.com
      - acme.com
    fa_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
"""

RETURN = r"""
"""

HAS_PURITY_FB = True
try:
    from purity_fb import Dns
except ImportError:
    HAS_PURITY_FB = False


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_blade,
    purefb_argument_spec,
)


def remove(duplicate):
    final_list = []
    for num in duplicate:
        if num not in final_list:
            final_list.append(num)
    return final_list


def delete_dns(module, blade):
    """Delete DNS Settings"""
    changed = True
    if not module.check_mode:
        changed = False
        current_dns = blade.dns.list_dns()
        if current_dns.items[0].domain or current_dns.items[0].nameservers != []:
            try:
                blade.dns.update_dns(dns_settings=Dns(domain="", nameservers=[]))
                changed = True
            except Exception:
                module.fail_json(msg="Deletion of DNS settings failed")
    module.exit_json(changed=changed)


def update_dns(module, blade):
    """Set DNS Settings"""
    changed = False
    current_dns = blade.dns.list_dns()
    if module.params["domain"]:
        if current_dns.items[0].domain != module.params["domain"]:
            changed = True
            if not module.check_mode:
                try:
                    blade.dns.update_dns(
                        dns_settings=Dns(domain=module.params["domain"])
                    )
                except Exception:
                    module.fail_json(msg="Update of DNS domain failed")
    if module.params["nameservers"]:
        if sorted(module.params["nameservers"]) != sorted(
            current_dns.items[0].nameservers
        ):
            changed = True
            if not module.check_mode:
                try:
                    blade.dns.update_dns(
                        dns_settings=Dns(nameservers=module.params["nameservers"])
                    )
                except Exception:
                    module.fail_json(msg="Update of DNS nameservers failed")
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            nameservers=dict(type="list", elements="str"),
            search=dict(type="list", elements="str"),
            domain=dict(type="str"),
            state=dict(type="str", default="present", choices=["absent", "present"]),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_PURITY_FB:
        module.fail_json(msg="purity_fb sdk is required for this module")

    blade = get_blade(module)

    if module.params["state"] == "absent":
        delete_dns(module, blade)
    elif module.params["state"] == "present":
        if module.params["nameservers"]:
            module.params["nameservers"] = remove(module.params["nameservers"])
        if module.params["search"]:
            module.warn(
                "'search' parameter is deprecated and will be removed in Collection v1.6.0"
            )
        update_dns(module, blade)
    else:
        module.exit_json(changed=False)


if __name__ == "__main__":
    main()

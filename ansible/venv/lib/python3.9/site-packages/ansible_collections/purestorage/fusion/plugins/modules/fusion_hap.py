#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: fusion_hap
version_added: '1.0.0'
short_description: Manage host access policies in Pure Storage Fusion
description:
- Create or delete host access policies in Pure Storage Fusion.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
notes:
- Supports C(check mode).
- Setting passwords is not an idempotent action.
- Only iSCSI transport is currently supported.
- iSCSI CHAP is not yet supported.
options:
  name:
    description:
    - The name of the host access policy.
    type: str
    required: true
  display_name:
    description:
    - The human name of the host access policy.
    type: str
  state:
    description:
    - Define whether the host access policy should exist or not.
    - When removing host access policy all connected volumes must
      have been previously disconnected.
    type: str
    default: present
    choices: [ absent, present ]
  wwns:
    type: list
    elements: str
    description:
    - CURRENTLY NOT SUPPORTED.
    - List of wwns for the host access policy.
  iqn:
    type: str
    description:
    - IQN for the host access policy.
  nqn:
    type: str
    description:
    - CURRENTLY NOT SUPPORTED.
    - NQN for the host access policy.
  personality:
    type: str
    description:
    - Define which operating system the host is.
    default: linux
    choices: ['linux', 'windows', 'hpux', 'vms', 'aix', 'esxi', 'solaris', 'hitachi-vsp', 'oracle-vm-server']
  target_user:
    type: str
    description:
    - CURRENTLY NOT SUPPORTED.
    - Sets the target user name for CHAP authentication.
    - Required with I(target_password).
    - To clear the username/password pair use C(clear) as the password.
  target_password:
    type: str
    description:
    - CURRENTLY NOT SUPPORTED.
    - Sets the target password for CHAP authentication.
    - Password length between 12 and 255 characters.
    - To clear the username/password pair use C(clear) as the password.
  host_user:
    type: str
    description:
    - CURRENTLY NOT SUPPORTED.
    - Sets the host user name for CHAP authentication.
    - Required with I(host_password).
    - To clear the username/password pair use C(clear) as the password.
  host_password:
    type: str
    description:
    - CURRENTLY NOT SUPPORTED.
    - Sets the host password for CHAP authentication.
    - Password length between 12 and 255 characters.
    - To clear the username/password pair use C(clear) as the password.
extends_documentation_fragment:
- purestorage.fusion.purestorage.fusion
"""

EXAMPLES = r"""
- name: Create new AIX host access policy
  purestorage.fusion.fusion_hap:
    name: foo
    personality: aix
    iqn: "iqn.2005-03.com.RedHat:linux-host1"
    issuer_id: key_name
    private_key_file: "az-admin-private-key.pem"

- name: Delete host access policy
  purestorage.fusion.fusion_hap:
    name: foo
    state: absent
    issuer_id: key_name
    private_key_file: "az-admin-private-key.pem"
"""

RETURN = r"""
"""

try:
    import fusion as purefusion
except ImportError:
    pass

import re
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.fusion.plugins.module_utils.fusion import (
    fusion_argument_spec,
)

from ansible_collections.purestorage.fusion.plugins.module_utils.startup import (
    setup_fusion,
)
from ansible_collections.purestorage.fusion.plugins.module_utils.operations import (
    await_operation,
)


def _check_iqn(module, fusion):
    hap_api_instance = purefusion.HostAccessPoliciesApi(fusion)
    hosts = hap_api_instance.list_host_access_policies().items
    for host in hosts:
        if host.iqn == module.params["iqn"] and host.name != module.params["name"]:
            module.fail_json(
                msg="Supplied IQN {0} already used by host access policy {1}".format(
                    module.params["iqn"], host.name
                )
            )


def get_host(module, fusion):
    """Return host or None"""
    hap_api_instance = purefusion.HostAccessPoliciesApi(fusion)
    try:
        return hap_api_instance.get_host_access_policy(
            host_access_policy_name=module.params["name"]
        )
    except purefusion.rest.ApiException:
        return None


def create_hap(module, fusion):
    """Create a new host access policy"""
    hap_api_instance = purefusion.HostAccessPoliciesApi(fusion)
    changed = True
    if not module.check_mode:
        display_name = module.params["display_name"] or module.params["name"]

        op = hap_api_instance.create_host_access_policy(
            purefusion.HostAccessPoliciesPost(
                iqn=module.params["iqn"],
                personality=module.params["personality"],
                name=module.params["name"],
                display_name=display_name,
            )
        )
        await_operation(fusion, op)
    module.exit_json(changed=changed)


def delete_hap(module, fusion):
    """Delete a Host Access Policy"""
    hap_api_instance = purefusion.HostAccessPoliciesApi(fusion)
    changed = True
    if not module.check_mode:
        op = hap_api_instance.delete_host_access_policy(
            host_access_policy_name=module.params["name"]
        )
        await_operation(fusion, op)
    module.exit_json(changed=changed)


def main():
    argument_spec = fusion_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            state=dict(type="str", default="present", choices=["absent", "present"]),
            nqn=dict(
                type="str",
                removed_in_version="2.0.0",
                removed_from_collection="purestorage.fusion",
            ),
            iqn=dict(type="str"),
            wwns=dict(
                type="list",
                elements="str",
                removed_in_version="2.0.0",
                removed_from_collection="purestorage.fusion",
            ),
            host_password=dict(
                type="str",
                removed_in_version="2.0.0",
                removed_from_collection="purestorage.fusion",
                no_log=True,
            ),
            host_user=dict(
                type="str",
                removed_in_version="2.0.0",
                removed_from_collection="purestorage.fusion",
            ),
            target_password=dict(
                type="str",
                removed_in_version="2.0.0",
                removed_from_collection="purestorage.fusion",
                no_log=True,
            ),
            target_user=dict(
                type="str",
                removed_in_version="2.0.0",
                removed_from_collection="purestorage.fusion",
            ),
            display_name=dict(type="str"),
            personality=dict(
                type="str",
                default="linux",
                choices=[
                    "linux",
                    "windows",
                    "hpux",
                    "vms",
                    "aix",
                    "esxi",
                    "solaris",
                    "hitachi-vsp",
                    "oracle-vm-server",
                ],
            ),
        )
    )

    required_if = [["state", "present", ["personality", "iqn"]]]

    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
        required_if=required_if,
    )
    fusion = setup_fusion(module)

    if module.params["nqn"]:
        module.warn(
            "`nqn` parameter is deprecated and will be removed in version 2.0.0"
        )
    if module.params["wwns"]:
        module.warn(
            "`wwns` parameter is deprecated and will be removed in version 2.0.0"
        )
    if module.params["host_password"]:
        module.warn(
            "`host_password` parameter is deprecated and will be removed in version 2.0.0"
        )
    if module.params["host_user"]:
        module.warn(
            "`host_user` parameter is deprecated and will be removed in version 2.0.0"
        )
    if module.params["target_password"]:
        module.warn(
            "`target_password` parameter is deprecated and will be removed in version 2.0.0"
        )
    if module.params["target_user"]:
        module.warn(
            "`target_user` parameter is deprecated and will be removed in version 2.0.0"
        )

    hap_pattern = re.compile("^[a-zA-Z0-9]([a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?$")
    iqn_pattern = re.compile(
        r"^iqn\.\d{4}-\d{2}((?<!-)\.(?!-)[a-zA-Z0-9\-]+){1,63}(?<!-)(?<!\.)(:(?!:)[^,\s'\"]+)?$"
    )

    if not hap_pattern.match(module.params["name"]):
        module.fail_json(
            msg="Host Access Policy {0} does not conform to naming convention".format(
                module.params["name"]
            )
        )

    if module.params["iqn"] is not None and not iqn_pattern.match(module.params["iqn"]):
        module.fail_json(
            msg="IQN {0} is not a valid iSCSI IQN".format(module.params["name"])
        )

    state = module.params["state"]
    host = get_host(module, fusion)
    _check_iqn(module, fusion)

    if host is None and state == "present":
        create_hap(module, fusion)
    elif host is not None and state == "absent":
        delete_hap(module, fusion)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

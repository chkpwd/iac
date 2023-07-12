#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: fusion_pp
version_added: '1.0.0'
short_description:  Manage protection policies in Pure Storage Fusion
description:
- Manage protection policies in Pure Storage Fusion.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
notes:
- Supports C(check mode).
options:
  name:
    description:
    - The name of the protection policy.
    type: str
    required: true
  state:
    description:
    - Define whether the protection policy should exist or not.
    default: present
    choices: [ present, absent ]
    type: str
  display_name:
    description:
    - The human name of the protection policy.
    - If not provided, defaults to I(name).
    type: str
  local_rpo:
    description:
    - Recovery Point Objective for snapshots.
    - Value should be specified in minutes.
    - Minimum value is 10 minutes.
    type: str
  local_retention:
    description:
    - Retention Duration for periodic snapshots.
    - Minimum value is 10 minutes.
    - Value can be provided as m(inutes), h(ours),
      d(ays), w(eeks), or y(ears).
    - If no unit is provided, minutes are assumed.
    type: str
extends_documentation_fragment:
- purestorage.fusion.purestorage.fusion
"""

EXAMPLES = r"""
- name: Create new protection policy foo
  purestorage.fusion.fusion_pp:
    name: foo
    local_rpo: 10
    local_retention: 4d
    display_name: "foo pp"
    issuer_id: key_name
    private_key_file: "az-admin-private-key.pem"

- name: Delete protection policy foo
  purestorage.fusion.fusion_pp:
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

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.fusion.plugins.module_utils.fusion import (
    fusion_argument_spec,
)

from ansible_collections.purestorage.fusion.plugins.module_utils.parsing import (
    parse_minutes,
)

from ansible_collections.purestorage.fusion.plugins.module_utils.startup import (
    setup_fusion,
)
from ansible_collections.purestorage.fusion.plugins.module_utils.operations import (
    await_operation,
)


def get_pp(module, fusion):
    """Return Protection Policy or None"""
    pp_api_instance = purefusion.ProtectionPoliciesApi(fusion)
    try:
        return pp_api_instance.get_protection_policy(
            protection_policy_name=module.params["name"]
        )
    except purefusion.rest.ApiException:
        return None


def create_pp(module, fusion):
    """Create Protection Policy"""

    pp_api_instance = purefusion.ProtectionPoliciesApi(fusion)
    local_rpo = parse_minutes(module, module.params["local_rpo"])
    local_retention = parse_minutes(module, module.params["local_retention"])
    if local_retention < 1:
        module.fail_json(msg="Local Retention must be a minimum of 1 minutes")
    if local_rpo < 10:
        module.fail_json(msg="Local RPO must be a minimum of 10 minutes")
    changed = True
    if not module.check_mode:
        if not module.params["display_name"]:
            display_name = module.params["name"]
        else:
            display_name = module.params["display_name"]
        op = pp_api_instance.create_protection_policy(
            purefusion.ProtectionPolicyPost(
                name=module.params["name"],
                display_name=display_name,
                objectives=[
                    purefusion.RPO(type="RPO", rpo="PT" + str(local_rpo) + "M"),
                    purefusion.Retention(
                        type="Retention", after="PT" + str(local_retention) + "M"
                    ),
                ],
            )
        )
        await_operation(fusion, op)

    module.exit_json(changed=changed)


def delete_pp(module, fusion):
    """Delete Protection Policy"""
    pp_api_instance = purefusion.ProtectionPoliciesApi(fusion)
    changed = True
    if not module.check_mode:
        op = pp_api_instance.delete_protection_policy(
            protection_policy_name=module.params["name"],
        )
        await_operation(fusion, op)

    module.exit_json(changed=changed)


def main():
    """Main code"""
    argument_spec = fusion_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            display_name=dict(type="str"),
            local_rpo=dict(type="str"),
            local_retention=dict(type="str"),
            state=dict(type="str", default="present", choices=["present", "absent"]),
        )
    )
    module = AnsibleModule(argument_spec, supports_check_mode=True)
    fusion = setup_fusion(module)

    state = module.params["state"]
    policy = get_pp(module, fusion)

    if not policy and state == "present":
        module.fail_on_missing_params(["local_rpo", "local_retention"])
        create_pp(module, fusion)
    elif policy and state == "absent":
        delete_pp(module, fusion)
    else:
        module.exit_json(changed=False)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

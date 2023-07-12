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
module: purefa_snmp_agent
version_added: '1.16.0'
short_description: Configure the FlashArray SNMP Agent
description:
- Manage the I(localhost) SNMP Agent on a Pure Storage FlashArray.
- This module is not idempotent and will always modify the SNMP Agent
  due to hidden parameters that cannot be compared to the task parameters.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    type: str
    description:
    - Used to set or clear the SNMP v2c community string or the SNMP v3
      auth and privacy protocols.
    choices: [ absent, present ]
    default: present
  user:
    type: str
    description:
    - SNMP v3 only. User ID which must be between 1 and 32 characters.
  version:
    type: str
    description:
    - Version of SNMP protocol to use for the manager.
    choices: [ v2c, v3 ]
    default: v2c
  community:
    type: str
    description:
    - SNMP v2c only. Manager community ID under which Purity//FA is to
      communicate with the specified managers.
    - To remove the string set I(state) to I(absent) with I(version)
      set to I(v2c)
  auth_passphrase:
    type: str
    description:
    - SNMP v3 only. Passphrade used by Purity//FA to authenticate the
      array wit hthe specified managers.
    - Must be between 8 and 63 non-space ASCII characters.
  auth_protocol:
    type: str
    description:
    - SNMP v3 only. Encryption protocol to use
    - To remove the privacy and auth protocols set I(state) to
      I(absent) with I(version) set to I(v3)
    choices: [ MD5, SHA ]
  privacy_passphrase:
    type: str
    description:
    - SNMP v3 only. Passphrase to encrypt SNMP messages.
      Must be between 8 and 63 non-space ASCII characters.
  privacy_protocol:
    type: str
    description:
    - SNMP v3 only. Encryption protocol to use
    - To remove the privacy and auth protocols set I(state) to
      I(absent) with I(version) set to I(v3)
    choices: [ AES, DES ]
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Clear SNMP agent v2c community string
  purestorage.flasharray.purefa_snmp_agent:
    version: v2c
    state: absent
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
- name: Clear SNMP agent v3 auth and privacy protocols
  purestorage.flasharray.purefa_snmp_agent:
    version: v3
    state: absent
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
- name: Update v2c SNMP agent
  puretorage.flasharray.purefa_snmp_agent:
    version: v2c
    community: public
    host: 10.21.22.23
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
- name: Update v3 SNMP manager
  puretorage.flasharray.purefa_snmp_agent:
    version: v3
    auth_protocol: MD5
    auth_passphrase: password
    host: 10.21.22.23
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""

HAS_PURESTORAGE = True
try:
    from pypureclient import flasharray
except ImportError:
    HAS_PURESTORAGE = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_system,
    get_array,
    purefa_argument_spec,
)

MIN_REQUIRED_API_VERSION = "2.1"


def update_agent(module, array, agent):
    """Update SNMP Agent"""
    changed = False
    if module.params["version"] == "v2c":
        changed = True
        if not module.check_mode:
            if module.params["state"] == "delete":
                community = ""
            elif module.params["state"] == "present" and module.params["community"]:
                community = module.params["community"]
            else:
                community = ""
            res = array.patch_snmp_agents(
                snmp_agent=flasharray.SnmpAgentPatch(
                    name="localhost",
                    version="v2c",
                    v2c=flasharray.SnmpV2c(community=community),
                )
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to update SNMP agent.Error: {0}".format(
                        res.errors[0].message
                    )
                )
    else:
        if module.params["state"] == "delete":
            changed = True
            v3 = flasharray.SnmpV3Patch(
                auth_protocol="",
                privacy_protocol="",
                user=module.params["user"],
            )
        elif module.params["auth_protocol"] and module.params["privacy_protocol"]:
            changed = True
            v3 = flasharray.SnmpV3Patch(
                auth_passphrase=module.params["auth_passphrase"],
                auth_protocol=module.params["auth_protocol"],
                privacy_passphrase=module.params["privacy_passphrase"],
                privacy_protocol=module.params["privacy_protocol"],
                user=module.params["user"],
            )
        elif module.params["auth_protocol"] and not module.params["privacy_protocol"]:
            changed = True
            v3 = flasharray.SnmpV3Patch(
                auth_passphrase=module.params["auth_passphrase"],
                auth_protocol=module.params["auth_protocol"],
                user=module.params["user"],
            )
        elif not module.params["auth_protocol"] and module.params["privacy_protocol"]:
            changed = True
            v3 = flasharray.SnmpV3Patch(
                privacy_passphrase=module.params["privacy_passphrase"],
                privacy_protocol=module.params["privacy_protocol"],
                user=module.params["user"],
            )
        elif (
            not module.params["auth_protocol"] and not module.params["privacy_protocol"]
        ):
            changed = True
            v3 = flasharray.SnmpV3Patch(user=module.params["user"])

        if not module.check_mode:
            res = array.patch_snmp_agents(
                snmp_agent=flasharray.SnmpAgentPatch(
                    name="localhost",
                    version=module.params["version"],
                    v3=v3,
                )
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to update SNMP agent.Error: {0}".format(
                        res.errors[0].message
                    )
                )

    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="present", choices=["absent", "present"]),
            user=dict(type="str"),
            auth_passphrase=dict(type="str", no_log=True),
            auth_protocol=dict(type="str", choices=["MD5", "SHA"]),
            privacy_passphrase=dict(type="str", no_log=True),
            privacy_protocol=dict(type="str", choices=["AES", "DES"]),
            version=dict(type="str", default="v2c", choices=["v2c", "v3"]),
            community=dict(type="str"),
        )
    )

    required_together = [
        ["auth_passphrase", "auth_protocol"],
        ["privacy_passphrase", "privacy_protocol"],
    ]
    required_if = [
        ["version", "v3", ["user"]],
    ]

    module = AnsibleModule(
        argument_spec,
        required_together=required_together,
        required_if=required_if,
        supports_check_mode=True,
    )

    array = get_system(module)
    api_version = array._list_available_rest_versions()

    if MIN_REQUIRED_API_VERSION not in api_version:
        module.fail_json(
            msg="FlashArray REST version not supported. "
            "Minimum version required: {0}".format(MIN_REQUIRED_API_VERSION)
        )
    array = get_array(module)

    agent = list(array.get_snmp_agents().items)
    if module.params["version"] == "v3":
        if module.params["auth_passphrase"] and (
            8 > len(module.params["auth_passphrase"]) > 32
        ):
            module.fail_json(msg="auth_password must be between 8 and 32 characters")
        if (
            module.params["privacy_passphrase"]
            and 8 > len(module.params["privacy_passphrase"]) > 63
        ):
            module.fail_json(msg="privacy_password must be between 8 and 63 characters")
    update_agent(module, array, agent)
    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

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
module: purefb_snmp_mgr
version_added: '1.0.0'
short_description: Configure FlashBlade SNMP Managers
description:
- Manage SNMP managers on a Pure Storage FlashBlade.
- This module is not idempotent and will always modify an
  existing SNMP manager due to hidden parameters that cannot
  be compared to the play parameters.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - Name of SNMP Manager
    required: true
    type: str
  state:
    description:
    - Create or delete SNMP manager
    type: str
    default: present
    choices: [ absent, present ]
  auth_passphrase:
    type: str
    description:
    - SNMPv3 only. Passphrase of 8 - 32 characters.
  auth_protocol:
    type: str
    description:
    - SNMP v3 only. Hash algorithm to use
    choices: [ MD5, SHA ]
  community:
    type: str
    description:
    - SNMP v2c only. Manager community ID. Between 1 and 32 characters long.
  host:
    type: str
    description:
    - IPv4 or IPv6 address or FQDN to send trap messages to.
  user:
    type: str
    description:
    - SNMP v3 only. User ID recognized by the specified SNMP manager.
      Must be between 1 and 32 characters.
  version:
    type: str
    description:
    - Version of SNMP protocol to use for the manager.
    choices: [ v2c, v3 ]
  notification:
    type: str
    description:
    - Action to perform on event.
    default: trap
    choices: [ inform, trap ]
  privacy_passphrase:
    type: str
    description:
    - SNMPv3 only. Passphrase to encrypt SNMP messages.
      Must be between 8 and 63 non-space ASCII characters.
  privacy_protocol:
    type: str
    description:
    - SNMP v3 only. Encryption protocol to use
    choices: [ AES, DES ]
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Delete exisitng SNMP manager
  purestorage.flashblade.purefb_snmp_mgr:
    name: manager1
    state: absent
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Create v2c SNMP manager
  purestorage.flashblade.purefb_snmp_mgr:
    name: manager1
    community: public
    host: 10.21.22.23
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Create v3 SNMP manager
  purestorage.flashblade.purefb_snmp_mgr:
    name: manager2
    version: v3
    auth_protocol: MD5
    auth_passphrase: password
    host: 10.21.22.23
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Update existing SNMP manager
  purestorage.flashblade.purefb_snmp_mgr:
    name: manager1
    community: private
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
"""

RETURN = r"""
"""


HAS_PURITY_FB = True
try:
    from purity_fb import SnmpManager, SnmpV2c, SnmpV3
except ImportError:
    HAS_PURITY_FB = False


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_blade,
    purefb_argument_spec,
)


MIN_REQUIRED_API_VERSION = "1.9"


def update_manager(module, blade):
    """Update SNMP Manager"""
    changed = False
    try:
        mgr = blade.snmp_managers.list_snmp_managers(names=[module.params["name"]])
    except Exception:
        module.fail_json(
            msg="Failed to get configuration for SNMP manager {0}.".format(
                module.params["name"]
            )
        )
    current_attr = {
        "community": mgr.items[0].v2c.community,
        "notification": mgr.items[0].notification,
        "host": mgr.items[0].host,
        "version": mgr.items[0].version,
        "auth_passphrase": mgr.items[0].v3.auth_passphrase,
        "auth_protocol": mgr.items[0].v3.auth_protocol,
        "privacy_passphrase": mgr.items[0].v3.privacy_passphrase,
        "privacy_protocol": mgr.items[0].v3.privacy_protocol,
        "user": mgr.items[0].v3.user,
    }
    new_attr = {
        "community": module.params["community"],
        "notification": module.params["notification"],
        "host": module.params["host"],
        "version": module.params["version"],
        "auth_passphrase": module.params["auth_passphrase"],
        "auth_protocol": module.params["auth_protocol"],
        "privacy_passphrase": module.params["privacy_passphrase"],
        "privacy_protocol": module.params["privacy_protocol"],
        "user": module.params["user"],
    }
    if current_attr != new_attr:
        changed = True
        if not module.check_mode:
            if new_attr["version"] == "v2c":
                updated_v2c_attrs = SnmpV2c(community=new_attr["community"])
                updated_v2c_manager = SnmpManager(
                    host=new_attr["host"],
                    notification=new_attr["notification"],
                    version="v2c",
                    v2c=updated_v2c_attrs,
                )
                try:
                    blade.snmp_managers.update_snmp_managers(
                        names=[module.params["name"]], snmp_manager=updated_v2c_manager
                    )
                except Exception:
                    module.fail_json(
                        msg="Failed to update v2c SNMP manager {0}.".format(
                            module.params["name"]
                        )
                    )
            else:
                updated_v3_attrs = SnmpV3(
                    auth_protocol=new_attr["auth_protocol"],
                    auth_passphrase=new_attr["auth_passphrase"],
                    privacy_protocol=new_attr["privacy_protocol"],
                    privacy_passphrase=new_attr["privacy_passphrase"],
                    user=new_attr["user"],
                )
                updated_v3_manager = SnmpManager(
                    host=new_attr["host"],
                    notification=new_attr["notification"],
                    version="v3",
                    v3=updated_v3_attrs,
                )
                try:
                    blade.snmp_managers.update_snmp_managers(
                        names=[module.params["name"]], snmp_manager=updated_v3_manager
                    )
                except Exception:
                    module.fail_json(
                        msg="Failed to update v3 SNMP manager {0}.".format(
                            module.params["name"]
                        )
                    )

    module.exit_json(changed=changed)


def delete_manager(module, blade):
    """Delete SNMP Manager"""
    changed = True
    if not module.check_mode:
        try:
            blade.snmp_managers.delete_snmp_managers(names=[module.params["name"]])
        except Exception:
            module.fail_json(
                msg="Delete SNMP manager {0} failed".format(module.params["name"])
            )
    module.exit_json(changed=changed)


def create_manager(module, blade):
    """Create SNMP Manager"""
    changed = True
    if not module.check_mode:
        if not module.params["version"]:
            module.fail_json(msg="SNMP version required to create a new manager")
        if module.params["version"] == "v2c":
            v2_attrs = SnmpV2c(community=module.params["community"])
            new_v2_manager = SnmpManager(
                host=module.params["host"],
                notification=module.params["notification"],
                version="v2c",
                v2c=v2_attrs,
            )
            try:
                blade.snmp_managers.create_snmp_managers(
                    names=[module.params["name"]], snmp_manager=new_v2_manager
                )
            except Exception:
                module.fail_json(
                    msg="Failed to create v2c SNMP manager {0}.".format(
                        module.params["name"]
                    )
                )
        else:
            v3_attrs = SnmpV3(
                auth_protocol=module.params["auth_protocol"],
                auth_passphrase=module.params["auth_passphrase"],
                privacy_protocol=module.params["privacy_protocol"],
                privacy_passphrase=module.params["privacy_passphrase"],
                user=module.params["user"],
            )
            new_v3_manager = SnmpManager(
                host=module.params["host"],
                notification=module.params["notification"],
                version="v3",
                v3=v3_attrs,
            )
            try:
                blade.snmp_managers.create_snmp_managers(
                    names=[module.params["name"]], snmp_manager=new_v3_manager
                )
            except Exception:
                module.fail_json(
                    msg="Failed to create v3 SNMP manager {0}.".format(
                        module.params["name"]
                    )
                )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            host=dict(type="str"),
            state=dict(type="str", default="present", choices=["absent", "present"]),
            user=dict(type="str"),
            notification=dict(type="str", choices=["inform", "trap"], default="trap"),
            auth_passphrase=dict(type="str", no_log=True),
            auth_protocol=dict(type="str", choices=["MD5", "SHA"]),
            privacy_passphrase=dict(type="str", no_log=True),
            privacy_protocol=dict(type="str", choices=["AES", "DES"]),
            version=dict(type="str", choices=["v2c", "v3"]),
            community=dict(type="str"),
        )
    )

    required_together = [
        ["auth_passphrase", "auth_protocol"],
        ["privacy_passphrase", "privacy_protocol"],
    ]
    required_if = [
        ["version", "v2c", ["community", "host"]],
        ["version", "v3", ["host", "user"]],
    ]

    module = AnsibleModule(
        argument_spec,
        required_together=required_together,
        required_if=required_if,
        supports_check_mode=True,
    )

    state = module.params["state"]
    blade = get_blade(module)
    api_version = blade.api_version.list_versions().versions

    if MIN_REQUIRED_API_VERSION not in api_version:
        module.fail_json(msg="Purity//FB must be upgraded to support this module.")

    if not HAS_PURITY_FB:
        module.fail_json(msg="purity_fb SDK is required for this module")

    mgr_configured = False
    mgrs = blade.snmp_managers.list_snmp_managers()
    for mgr in range(0, len(mgrs.items)):
        if mgrs.items[mgr].name == module.params["name"]:
            mgr_configured = True
            break
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
    if state == "absent" and mgr_configured:
        delete_manager(module, blade)
    elif mgr_configured and state == "present":
        update_manager(module, blade)
    elif not mgr_configured and state == "present":
        create_manager(module, blade)
    else:
        module.exit_json(changed=False)


if __name__ == "__main__":
    main()

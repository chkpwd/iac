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
module: purefb_user
version_added: '1.0.0'
short_description: Modify FlashBlade user accounts
description:
- Modify user on a Pure Stoage FlashBlade.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - The name of the user account
    type: str
  password:
    description:
    - Password for the local user.
    - Only applies to the local user 'pureuser'
    type: str
  old_password:
    description:
    - If changing an existing password, you must provide the old password for security
    - Only applies to the local user 'pureuser'
    type: str
  public_key:
    description:
    - The API clients PEM formatted (Base64 encoded) RSA public key.
    - Include the I(—–BEGIN PUBLIC KEY—–) and I(—–END PUBLIC KEY—–) lines
    type: str
    version_added: "1.8.0"
  clear_lock:
    description:
    - Clear user lockout flag
    type: bool
    default: false
    version_added: "1.8.0"
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Change password for local user (NOT IDEMPOTENT)
  purestorage.flashblade.purefb_user:
    name: pureuser
    password: anewpassword
    old_password: apassword
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6

- name: Set public key for user
  purestorage.flashblade.purefb_user:
    name: fred
    public_key: "{{lookup('file', 'public_pem_file') }}"
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6

- name: Clear user lockout
  purestorage.flashblade.purefb_user:
    name: fred
    clear_lock: true
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
"""

RETURN = r"""
"""

HAS_PURITY_FB = True
try:
    from purity_fb import Admin
except ImportError:
    HAS_PURITY_FB = False

HAS_PURESTORAGE = True
try:
    from pypureclient.flashblade import AdminPatch
except ImportError:
    HAS_PURESTORAGE = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_blade,
    get_system,
    purefb_argument_spec,
)

MIN_REQUIRED_API_VERSION = "1.3"
MIN_KEY_API_VERSION = "2.1"
MIN_LOCK_API_VERSION = "2.3"


def update_user(module, blade):
    """Create or Update Local User Account"""
    changed = False
    if module.params["password"] and module.params["name"].lower() == "pureuser":
        if module.params["password"] != module.params["old_password"]:
            changed = True
            if not module.check_mode:
                try:
                    new_admin = Admin()
                    new_admin.password = module.params["password"]
                    new_admin.old_password = module.params["old_password"]
                    blade.admins.update_admins(names=["pureuser"], admin=new_admin)
                except Exception:
                    module.fail_json(
                        msg="Local User {0}: Password reset failed. "
                        "Check passwords. One of these is incorrect.".format(
                            module.params["name"]
                        )
                    )
        else:
            module.fail_json(
                msg="Local User Account {0}: Password change failed - "
                "Old and new passwords are the same".format(module.params["name"])
            )
    if module.params["password"] and module.params["name"].lower() != "pureuser":
        module.fail_json(msg="Changing password for remote accounts is not supported.")
    api_version = blade.api_version.list_versions().versions
    if MIN_KEY_API_VERSION in api_version:
        bladev2 = get_system(module)
        try:
            user_data = list(bladev2.get_admins(names=[module.params["name"]]).items)[0]
        except AttributeError:
            module.fail_json(
                msg="User {0} does not currently exist in the FlashBlade. "
                "Please login to this user before attempting to modify it.".format(
                    module.params["name"]
                )
            )
        current_key = user_data.public_key
        if module.params["public_key"] and current_key != module.params["public_key"]:
            changed = True
            if not module.check_mode:
                my_admin = AdminPatch(public_key=module.params["public_key"])
                res = bladev2.patch_admins(
                    names=[module.params["name"]], admin=my_admin
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to change public_key for {0}.".format(
                            module.params["name"]
                        )
                    )
        if MIN_LOCK_API_VERSION in api_version:
            if user_data.locked and module.params["clear_lock"]:
                changed = True
                if not module.check_mode:
                    my_admin = AdminPatch(locked=False)
                    res = bladev2.patch_admins(
                        names=[module.params["name"]], admin=my_admin
                    )
                    if res.status_code != 200:
                        module.fail_json(
                            msg="Failed to unlock user {0}.".format(
                                module.params["name"]
                            )
                        )

    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str"),
            public_key=dict(type="str", no_log=True),
            password=dict(type="str", no_log=True),
            old_password=dict(type="str", no_log=True),
            clear_lock=dict(type="bool", default=False),
        )
    )

    required_together = [["password", "old_password"]]
    module = AnsibleModule(
        argument_spec, supports_check_mode=True, required_together=required_together
    )

    if not HAS_PURITY_FB:
        module.fail_json(msg="purity_fb sdk is required for this module")
    if not HAS_PURESTORAGE and module.params["public_key"]:
        module.fail_json(msg="py-pure-client sdk is required for to set public keys")

    blade = get_blade(module)
    api_version = blade.api_version.list_versions().versions
    if MIN_REQUIRED_API_VERSION not in api_version:
        module.fail_json(msg="Purity//FB must be upgraded to support this module.")

    update_user(module, blade)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

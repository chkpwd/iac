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
module: purefb_s3user
version_added: '1.0.0'
short_description: Create or delete FlashBlade Object Store account users
description:
- Create or delete object store account users on a Pure Stoage FlashBlade.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Create or delete object store account user
    - Remove a specified access key for a user
    default: present
    choices: [ absent, present, remove_key ]
    type: str
  name:
    description:
    - The name of object store user
    type: str
    required: true
  account:
    description:
    - The name of object store account associated with user
    type: str
    required: true
  access_key:
    description:
    - Create secret access key.
    - Key can be exposed using the I(debug) module
    - If enabled this will override I(imported_key)
    type: bool
    default: false
  remove_key:
    description:
    - Access key to be removed from user
    type: str
    version_added: "1.5.0"
  imported_key:
    description:
    - Access key of imported credentials
    type: str
    version_added: "1.4.0"
  imported_secret:
    description:
    - Access key secret for access key to import
    type: str
    version_added: "1.4.0"
  policy:
    description:
    - User Access Policies to be assigned to user on creation
    - To amend policies use the I(purestorage.flashblade.purefb_userpolicy) module
    - If not specified, I(pure\:policy/full-access) will be added
    type: list
    elements: str
    version_added: "1.6.0"
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Create object store user (with access ID and key) foo in account bar
  purestorage.flashblade.purefb_s3user:
    name: foo
    account: bar
    access_key: true
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
  register: result

- debug:
    msg: "S3 User: {{ result['s3user_info'] }}"

- name: Create object store user (with access ID and key) foo in account bar with access policy (Purity 3.2 and higher)
  purestorage.flashblade.purefb_s3user:
    name: foo
    account: bar
    access_key: true
    policy:
      - pure:policy/safemode-configure
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Create object store user foo using imported key/secret in account bar
  purestorage.flashblade.purefb_s3user:
    name: foo
    account: bar
    imported_key: "PSABSSZRHPMEDKHMAAJPJBONPJGGDDAOFABDGLBJLHO"
    imported_secret: "BAG61F63105e0d3669/e066+5C5DFBE2c127d395LBGG"
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Delete object store user foo in account bar
  purestorage.flashblade.purefb_s3user:
    name: foo
    account: bar
    state: absent
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""


HAS_PURITY_FB = True
try:
    from purity_fb import ObjectStoreAccessKey, ObjectStoreAccessKeyPost
except ImportError:
    HAS_PURITY_FB = False


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_blade,
    get_system,
    purefb_argument_spec,
)


MIN_REQUIRED_API_VERSION = "1.3"
IMPORT_KEY_API_VERSION = "1.10"
POLICY_API_VERSION = "2.0"


def get_s3acc(module, blade):
    """Return Object Store Account or None"""
    s3acc = None
    accts = blade.object_store_accounts.list_object_store_accounts()
    for acct in range(0, len(accts.items)):
        if accts.items[acct].name == module.params["account"]:
            s3acc = accts.items[acct]
    return s3acc


def get_s3user(module, blade):
    """Return Object Store Account or None"""
    full_user = module.params["account"] + "/" + module.params["name"]
    s3user = None
    s3users = blade.object_store_users.list_object_store_users()
    for user in range(0, len(s3users.items)):
        if s3users.items[user].name == full_user:
            s3user = s3users.items[user]
    return s3user


def update_s3user(module, blade):
    """Update Object Store User"""
    changed = False
    exists = False
    s3user_facts = {}
    user = module.params["account"] + "/" + module.params["name"]
    if module.params["access_key"] or module.params["imported_key"]:
        key_count = 0
        keys = blade.object_store_access_keys.list_object_store_access_keys()
        for key in range(0, len(keys.items)):
            if module.params["imported_key"]:
                versions = blade.api_version.list_versions().versions
                if IMPORT_KEY_API_VERSION in versions:
                    if keys.items[key].name == module.params["imported_key"]:
                        module.warn("Imported key provided already belongs to a user")
                        exists = True
            if keys.items[key].user.name == user:
                key_count += 1
        if not exists:
            if key_count < 2:
                changed = True
                if not module.check_mode:
                    try:
                        if (
                            module.params["access_key"]
                            and module.params["imported_key"]
                        ):
                            module.warn("'access_key: true' overrides imported keys")
                        if module.params["access_key"]:
                            result = blade.object_store_access_keys.create_object_store_access_keys(
                                object_store_access_key=ObjectStoreAccessKey(
                                    user={"name": user}
                                )
                            )
                            s3user_facts["fb_s3user"] = {
                                "user": user,
                                "access_key": result.items[0].secret_access_key,
                                "access_id": result.items[0].name,
                            }
                        else:
                            if IMPORT_KEY_API_VERSION in versions:
                                blade.object_store_access_keys.create_object_store_access_keys(
                                    names=[module.params["imported_key"]],
                                    object_store_access_key=ObjectStoreAccessKeyPost(
                                        user={"name": user},
                                        secret_access_key=module.params[
                                            "imported_secret"
                                        ],
                                    ),
                                )
                    except Exception:
                        if module.params["imported_key"]:
                            module.fail_json(
                                msg="Object Store User {0}: Access Key import failed".format(
                                    user
                                )
                            )
                        else:
                            module.fail_json(
                                msg="Object Store User {0}: Access Key creation failed".format(
                                    user
                                )
                            )
            else:
                module.warn(
                    "Object Store User {0}: Maximum Access Key count reached".format(
                        user
                    )
                )
    module.exit_json(changed=changed, s3user_info=s3user_facts)


def create_s3user(module, blade):
    """Create Object Store Account"""
    s3user_facts = {}
    changed = True
    if not module.check_mode:
        user = module.params["account"] + "/" + module.params["name"]
        blade.object_store_users.create_object_store_users(names=[user])
        if module.params["access_key"] and module.params["imported_key"]:
            module.warn("'access_key: true' overrides imported keys")
        if module.params["access_key"]:
            try:
                result = blade.object_store_access_keys.create_object_store_access_keys(
                    object_store_access_key=ObjectStoreAccessKey(user={"name": user})
                )
                s3user_facts["fb_s3user"] = {
                    "user": user,
                    "access_key": result.items[0].secret_access_key,
                    "access_id": result.items[0].name,
                }
            except Exception:
                delete_s3user(module, blade, True)
                module.fail_json(
                    msg="Object Store User {0}: Creation failed".format(user)
                )
        else:
            if module.params["imported_key"]:
                versions = blade.api_version.list_versions().versions
                if IMPORT_KEY_API_VERSION in versions:
                    try:
                        blade.object_store_access_keys.create_object_store_access_keys(
                            names=[module.params["imported_key"]],
                            object_store_access_key=ObjectStoreAccessKeyPost(
                                user={"name": user},
                                secret_access_key=module.params["imported_secret"],
                            ),
                        )
                    except Exception:
                        delete_s3user(module, blade)
                        module.fail_json(
                            msg="Object Store User {0}: Creation failed with imported access key".format(
                                user
                            )
                        )
        if module.params["policy"]:
            blade = get_system(module)
            api_version = list(blade.get_versions().items)

            if POLICY_API_VERSION in api_version:
                policy_list = module.params["policy"]
                for policy in range(0, len(policy_list)):
                    if (
                        blade.get_object_store_access_policies(
                            names=[policy_list[policy]]
                        ).status_code
                        != 200
                    ):
                        module.warn(
                            "Policy {0} is not valid. Ignoring...".format(
                                policy_list[policy]
                            )
                        )
                        policy_list.remove(policy_list[policy])
                username = module.params["account"] + "/" + module.params["name"]
                for policy in range(0, len(policy_list)):
                    if not (
                        blade.get_object_store_users_object_store_access_policies(
                            member_names=[username], policy_names=[policy_list[policy]]
                        ).items
                    ):
                        res = (
                            blade.post_object_store_access_policies_object_store_users(
                                member_names=[username],
                                policy_names=[policy_list[policy]],
                            )
                        )
                        if res.status_code != 200:
                            module.warn(
                                "Failed to add policy {0} to account user {1}. Skipping...".format(
                                    policy_list[policy], username
                                )
                            )
                if "pure:policy/full-access" not in policy_list:
                    # User Create adds the pure:policy/full-access policy by default
                    # If we are specifying a list then remove this default value
                    blade.delete_object_store_access_policies_object_store_users(
                        member_names=[username],
                        policy_names=["pure:policy/full-access"],
                    )
            else:
                module.warn(
                    "FlashBlade REST version not supported for user access policies. Skipping..."
                )
    module.exit_json(changed=changed, s3user_info=s3user_facts)


def remove_key(module, blade):
    """Remove Access Key from User"""
    changed = False
    if not module.check_mode:
        try:
            keys = blade.object_store_access_keys.list_object_store_access_keys()
            for key in range(0, len(keys.items)):
                if keys.items[key].name == module.params["remove_key"]:
                    blade.object_store_access_keys.delete_object_store_access_keys(
                        names=[module.params["remove_key"]]
                    )
                    changed = True
        except Exception:
            module.fail_json(msg="Failed to correctly read or delete access keys")
    module.exit_json(changed=changed)


def delete_s3user(module, blade, internal=False):
    """Delete Object Store Account"""
    changed = True
    if not module.check_mode:
        user = module.params["account"] + "/" + module.params["name"]
        try:
            blade.object_store_users.delete_object_store_users(names=[user])
        except Exception:
            module.fail_json(
                msg="Object Store Account {0}: Deletion failed".format(
                    module.params["name"]
                )
            )
    if internal:
        return
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            name=dict(required=True, type="str"),
            account=dict(required=True, type="str"),
            access_key=dict(default="false", type="bool"),
            imported_key=dict(type="str", no_log=False),
            remove_key=dict(type="str", no_log=False),
            imported_secret=dict(type="str", no_log=True),
            policy=dict(type="list", elements="str"),
            state=dict(default="present", choices=["present", "absent", "remove_key"]),
        )
    )

    required_together = [["imported_key", "imported_secret"]]
    required_if = [["state", "remove_key", ["remove_key"]]]

    module = AnsibleModule(
        argument_spec,
        required_together=required_together,
        required_if=required_if,
        supports_check_mode=True,
    )

    if not HAS_PURITY_FB:
        module.fail_json(msg="purity_fb sdk is required for this module")

    state = module.params["state"]
    blade = get_blade(module)
    versions = blade.api_version.list_versions().versions

    if MIN_REQUIRED_API_VERSION not in versions:
        module.fail_json(
            msg="Minimum FlashBlade REST version required: {0}".format(
                MIN_REQUIRED_API_VERSION
            )
        )
    upper = False
    for element in module.params["account"]:
        if element.isupper():
            upper = True
            break
    if upper:
        module.warn("Changing account name to lowercase...")
        module.params["account"] = module.params["account"].lower()

    s3acc = get_s3acc(module, blade)
    if not s3acc:
        module.fail_json(
            msg="Object Store Account {0} does not exist".format(
                module.params["account"]
            )
        )

    s3user = get_s3user(module, blade)

    if state == "absent" and s3user:
        delete_s3user(module, blade)
    elif state == "present" and s3user:
        update_s3user(module, blade)
    elif not s3user and state == "present":
        create_s3user(module, blade)
    elif state == "remove_key" and s3user:
        remove_key(module, blade)
    else:
        module.exit_json(changed=False)


if __name__ == "__main__":
    main()

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
module: purefb_s3acc
version_added: '1.0.0'
short_description: Create or delete FlashBlade Object Store accounts
description:
- Create or delete object store accounts on a Pure Stoage FlashBlade.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Create or delete object store account
    default: present
    choices: [ absent, present ]
    type: str
  name:
    description:
    - The name of object store account
    type: str
    required: true
  quota:
    description:
    - The effective quota limit to be applied against the size of the account in bytes.
    - If set to '' (empty string), the account is unlimited in size.
    version_added: 1.11.0
    type: str
  hard_limit:
    description:
    - If set to true, the account size, as defined by I(quota_limit), is used as a hard limit quota.
    - If set to false, a hard limit quota will not be applied to the account, but soft quota alerts
      will still be sent if the account has a value set for I(quota_limit).
    version_added: 1.11.0
    type: bool
    default: false
  default_quota:
    description:
    - The value of this field will be used to configure the I(quota_limit) field of newly created buckets
      associated with this object store account, if the bucket creation does not specify its own value.
    - If set to '' (empty string), the bucket default is unlimited in size.
    version_added: 1.11.0
    type: str
  default_hard_limit:
    description:
    - The value of this field will be used to configure the I(hard_limit) field of newly created buckets
      associated with this object store account, if the bucket creation does not specify its own value.
    version_added: 1.11.0
    type: bool
    default: false
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Crrate object store account foo (with no quotas)
  purestorage.flashblade.purefb_s3acc:
    name: foo
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Create object store account foo (with quotas)
  purestorage.flashblade.purefb_s3acc:
    name: foo
    quota: 20480000
    hard_limit: true
    default_quota: 1024000
    default_hard_limit: false
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Delete object store account foo
  purestorage.flashblade.purefb_s3acc:
    name: foo
    state: absent
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""

HAS_PURESTORAGE = True
try:
    from pypureclient.flashblade import ObjectStoreAccountPatch, BucketDefaults
except ImportError:
    HAS_PURESTORAGE = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_blade,
    get_system,
    purefb_argument_spec,
)


MIN_REQUIRED_API_VERSION = "1.3"
QUOTA_API_VERSION = "2.1"


def get_s3acc(module, blade):
    """Return Object Store Account or None"""
    s3acc = None
    accts = blade.object_store_accounts.list_object_store_accounts()
    for acct in range(0, len(accts.items)):
        if accts.items[acct].name == module.params["name"]:
            s3acc = accts.items[acct]
    return s3acc


def update_s3acc(module):
    """Update Object Store Account"""
    changed = False
    blade = get_system(module)
    acc_settings = list(
        blade.get_object_store_accounts(names=[module.params["name"]]).items
    )[0]
    current_account = {
        "hard_limit": acc_settings.hard_limit_enabled,
        "default_hard_limit": acc_settings.bucket_defaults.hard_limit_enabled,
        "quota": str(acc_settings.quota_limit),
        "default_quota": str(acc_settings.bucket_defaults.quota_limit),
    }
    if current_account["quota"] == "None":
        current_account["quota"] = ""
    if current_account["default_quota"] == "None":
        current_account["default_quota"] = ""
    if module.params["quota"] is None:
        module.params["quota"] = current_account["quota"]
    if module.params["default_quota"] is None:
        module.params["default_quota"] = current_account["default_quota"]
    new_account = {
        "hard_limit": module.params["hard_limit"],
        "default_hard_limit": module.params["default_hard_limit"],
        "quota": module.params["quota"],
        "default_quota": module.params["default_quota"],
    }
    if new_account != current_account:
        changed = True
        if not module.check_mode:
            osa = ObjectStoreAccountPatch(
                hard_limit_enabled=new_account["hard_limit"],
                quota_limit=new_account["quota"],
                bucket_defaults=BucketDefaults(
                    hard_limit_enabled=new_account["default_hard_limit"],
                    quota_limit=new_account["default_quota"],
                ),
            )
            res = blade.patch_object_store_accounts(
                object_store_account=osa, names=[module.params["name"]]
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to update account {0}. "
                    "Error: {1}".format(module.params["name"], res.errors[0].message)
                )
    module.exit_json(changed=changed)


def create_s3acc(module, blade):
    """Create Object Store Account"""
    changed = True
    if not module.check_mode:
        try:
            blade.object_store_accounts.create_object_store_accounts(
                names=[module.params["name"]]
            )
        except Exception:
            module.fail_json(
                msg="Object Store Account {0}: Creation failed".format(
                    module.params["name"]
                )
            )
        if module.params["quota"] or module.params["default_quota"]:
            blade2 = get_system(module)
            if module.params["quota"] and not module.params["default_quota"]:
                osa = ObjectStoreAccountPatch(
                    hard_limit_enabled=module.params["hard_limit"],
                    quota_limit=module.params["quota"],
                )
            if not module.params["quota"] and module.params["default_quota"]:
                osa = ObjectStoreAccountPatch(
                    bucket_defaults=BucketDefaults(
                        hard_limit_enabled=module.params["default_hard_limit"],
                        quota_limit=module.params["default_quota"],
                    )
                )
            else:
                osa = ObjectStoreAccountPatch(
                    hard_limit_enabled=module.params["hard_limit"],
                    quota_limit=module.params["quota"],
                    bucket_defaults=BucketDefaults(
                        hard_limit_enabled=module.params["default_hard_limit"],
                        quota_limit=module.params["default_quota"],
                    ),
                )
            res = blade2.patch_object_store_accounts(
                object_store_account=osa, names=[module.params["name"]]
            )
            if res.status_code != 200:
                blade.object_store_accounts.delete_object_store_accounts(
                    names=[module.params["name"]]
                )
                module.fail_json(
                    msg="Failed to set quotas correctly for account {0}. "
                    "Error: {1}".format(module.params["name"], res.errors[0].message)
                )
    module.exit_json(changed=changed)


def delete_s3acc(module, blade):
    """Delete Object Store Account"""
    changed = True
    if not module.check_mode:
        count = len(
            blade.object_store_users.list_object_store_users(
                filter="name='" + module.params["name"] + "/*'"
            ).items
        )
        if count != 0:
            module.fail_json(
                msg="Remove all Users from Object Store Account {0} \
                                 before deletion".format(
                    module.params["name"]
                )
            )
        else:
            try:
                blade.object_store_accounts.delete_object_store_accounts(
                    names=[module.params["name"]]
                )
            except Exception:
                module.fail_json(
                    msg="Object Store Account {0}: Deletion failed".format(
                        module.params["name"]
                    )
                )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            name=dict(required=True, type="str"),
            hard_limit=dict(type="bool", default=False),
            default_hard_limit=dict(type="bool", default=False),
            quota=dict(type="str"),
            default_quota=dict(type="str"),
            state=dict(default="present", choices=["present", "absent"]),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    state = module.params["state"]
    blade = get_blade(module)
    versions = blade.api_version.list_versions().versions

    if MIN_REQUIRED_API_VERSION not in versions:
        module.fail_json(
            msg="Minimum FlashBlade REST version required: {0}".format(
                MIN_REQUIRED_API_VERSION
            )
        )

    if module.params["quota"] or module.params["default_quota"]:
        if not HAS_PURESTORAGE:
            module.fail_json(msg="py-pure-client sdk is required for to set quotas")
        if QUOTA_API_VERSION not in versions:
            module.fail_json(
                msg="Quotas require minimum FlashBlade REST version: {0}".format(
                    QUOTA_API_VERSION
                )
            )

    upper = False
    for element in module.params["name"]:
        if element.isupper():
            upper = True
            break
    if upper:
        module.warn("Changing account name to lowercase...")
        module.params["name"] = module.params["name"].lower()

    s3acc = get_s3acc(module, blade)

    if state == "absent" and s3acc:
        delete_s3acc(module, blade)
    elif state == "present" and s3acc:
        update_s3acc(module)
    elif not s3acc and state == "present":
        create_s3acc(module, blade)
    else:
        module.exit_json(changed=False)


if __name__ == "__main__":
    main()

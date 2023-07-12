#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2017, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}


DOCUMENTATION = """
---
module: purefb_bucket
version_added: "1.0.0"
short_description:  Manage Object Store Buckets on a  Pure Storage FlashBlade.
description:
    - This module managess object store (s3) buckets on Pure Storage FlashBlade.
author: Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
      - Bucket Name.
    required: true
    type: str
  account:
    description:
      - Object Store Account for Bucket.
    required: true
    type: str
  versioning:
    description:
      - State of S3 bucket versioning
    required: false
    default: absent
    type: str
    choices: [ "enabled", "suspended", "absent" ]
  state:
    description:
      - Create, delete or modifies a bucket.
    required: false
    default: present
    type: str
    choices: [ "present", "absent" ]
  eradicate:
    description:
      - Define whether to eradicate the bucket on delete or leave in trash.
    required: false
    type: bool
    default: false
  mode:
    description:
      - The type of bucket to be created. Also referred to a VSO Mode.
      - Requires Purity//FB 3.3.3 or higher
      - I(multi-site) type can only be used after feature is
        enabled by Pure Technical Support
    type: str
    choices: [ "classic", "multi-site" ]
    version_added: '1.10.0'
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = """
- name: Create new bucket named foo in account bar
  purestorage.flashblade.purefb_bucket:
    name: foo
    account: bar
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Delete bucket named foo in account bar
  purestorage.flashblade.purefb_bucket:
    name: foo
    account: bar
    state: absent
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Change bucket versioning state
  purestorage.flashblade.purefb_bucket:
    name: foo
    account: bar
    versioning: enabled
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Recover deleted bucket named foo in account bar
  purestorage.flashblade.purefb_bucket:
    name: foo
    account: bar
    state: present
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Eradicate bucket named foo in account bar
  purestorage.flashblade.purefb_bucket:
    name: foo
    account: bar
    state: absent
    eradicate: true
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
"""

RETURN = """
"""

HAS_PURITY_FB = True
try:
    from purity_fb import Bucket, Reference, BucketPatch, BucketPost
except ImportError:
    HAS_PURITY_FB = False

HAS_PYPURECLIENT = True
try:
    from pypureclient import flashblade
except ImportError:
    HAS_PYPURECLIENT = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_blade,
    get_system,
    purefb_argument_spec,
)


MIN_REQUIRED_API_VERSION = "1.5"
VERSIONING_VERSION = "1.9"
VSO_VERSION = "2.4"


def get_s3acc(module, blade):
    """Return Object Store Account or None"""
    s3acc = None
    accts = blade.object_store_accounts.list_object_store_accounts()
    for acct in range(0, len(accts.items)):
        if accts.items[acct].name == module.params["account"]:
            s3acc = accts.items[acct]
    return s3acc


def get_bucket(module, blade):
    """Return Bucket or None"""
    s3bucket = None
    buckets = blade.buckets.list_buckets()
    for bucket in range(0, len(buckets.items)):
        if buckets.items[bucket].name == module.params["name"]:
            s3bucket = buckets.items[bucket]
    return s3bucket


def create_bucket(module, blade):
    """Create bucket"""
    changed = True
    if not module.check_mode:
        try:
            api_version = blade.api_version.list_versions().versions
            if VSO_VERSION in api_version and module.params["mode"]:
                bladev2 = get_system(module)
                res = bladev2.post_buckets(
                    names=[module.params["name"]],
                    bucket=flashblade.BucketPost(
                        account=flashblade.Reference(name=module.params["account"]),
                        bucket_type=module.params["mode"],
                    ),
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Object Store Bucket {0} creation failed. Error: {1}".format(
                            module.params["name"],
                            res.errors[0].message,
                        )
                    )
            elif VERSIONING_VERSION in api_version:
                attr = BucketPost()
                attr.account = Reference(name=module.params["account"])
                blade.buckets.create_buckets(names=[module.params["name"]], bucket=attr)
            else:
                attr = Bucket()
                attr.account = Reference(name=module.params["account"])
                blade.buckets.create_buckets(
                    names=[module.params["name"]], account=attr
                )
            if (
                module.params["versioning"] != "absent"
                and VERSIONING_VERSION in api_version
            ):
                try:
                    blade.buckets.update_buckets(
                        names=[module.params["name"]],
                        bucket=BucketPatch(versioning=module.params["versioning"]),
                    )
                except Exception:
                    module.fail_json(
                        msg="Object Store Bucket {0} Created but versioning state failed".format(
                            module.params["name"]
                        )
                    )
        except Exception:
            module.fail_json(
                msg="Object Store Bucket {0}: Creation failed".format(
                    module.params["name"]
                )
            )
    module.exit_json(changed=changed)


def delete_bucket(module, blade):
    """Delete Bucket"""
    changed = True
    if not module.check_mode:
        try:
            api_version = blade.api_version.list_versions().versions
            if VERSIONING_VERSION in api_version:
                blade.buckets.update_buckets(
                    names=[module.params["name"]], bucket=BucketPatch(destroyed=True)
                )
            else:
                blade.buckets.update_buckets(
                    names=[module.params["name"]], destroyed=Bucket(destroyed=True)
                )
            if module.params["eradicate"]:
                try:
                    blade.buckets.delete_buckets(names=[module.params["name"]])
                except Exception:
                    module.fail_json(
                        msg="Object Store Bucket {0}: Eradication failed".format(
                            module.params["name"]
                        )
                    )
        except Exception:
            module.fail_json(
                msg="Object Store Bucket {0}: Deletion failed".format(
                    module.params["name"]
                )
            )
    module.exit_json(changed=changed)


def recover_bucket(module, blade):
    """Recover Bucket"""
    changed = True
    if not module.check_mode:
        try:
            api_version = blade.api_version.list_versions().versions
            if VERSIONING_VERSION in api_version:
                blade.buckets.update_buckets(
                    names=[module.params["name"]], bucket=BucketPatch(destroyed=False)
                )
            else:
                blade.buckets.update_buckets(
                    names=[module.params["name"]], destroyed=Bucket(destroyed=False)
                )
        except Exception:
            module.fail_json(
                msg="Object Store Bucket {0}: Recovery failed".format(
                    module.params["name"]
                )
            )
    module.exit_json(changed=changed)


def update_bucket(module, blade, bucket):
    """Update Bucket"""
    changed = False
    api_version = blade.api_version.list_versions().versions
    if VSO_VERSION in api_version:
        if module.params["mode"]:
            bladev2 = get_system(module)
            bucket_detail = bladev2.get_buckets(names=[module.params["name"]])
            if list(bucket_detail.items)[0].bucket_type != module.params["mode"]:
                module.warn("Changing bucket type is not permitted.")

    if VERSIONING_VERSION in api_version:
        if bucket.versioning != "none":
            if module.params["versioning"] == "absent":
                versioning = "suspended"
            else:
                versioning = module.params["versioning"]
            if bucket.versioning != versioning:
                changed = True
                if not module.check_mode:
                    try:
                        blade.buckets.update_buckets(
                            names=[module.params["name"]],
                            bucket=BucketPatch(versioning=versioning),
                        )
                        changed = True
                    except Exception:
                        module.fail_json(
                            msg="Object Store Bucket {0}: Versioning change failed".format(
                                module.params["name"]
                            )
                        )
        elif module.params["versioning"] != "absent":
            changed = True
            if not module.check_mode:
                try:
                    blade.buckets.update_buckets(
                        names=[module.params["name"]],
                        bucket=BucketPatch(versioning=module.params["versioning"]),
                    )
                    changed = True
                except Exception:
                    module.fail_json(
                        msg="Object Store Bucket {0}: Versioning change failed".format(
                            module.params["name"]
                        )
                    )
    module.exit_json(changed=changed)


def eradicate_bucket(module, blade):
    """Eradicate Bucket"""
    changed = True
    if not module.check_mode:
        try:
            blade.buckets.delete_buckets(names=[module.params["name"]])
        except Exception:
            module.fail_json(
                msg="Object Store Bucket {0}: Eradication failed".format(
                    module.params["name"]
                )
            )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            name=dict(required=True),
            account=dict(required=True),
            eradicate=dict(default="false", type="bool"),
            mode=dict(type="str", choices=["classic", "multi-site"]),
            versioning=dict(
                default="absent", choices=["enabled", "suspended", "absent"]
            ),
            state=dict(default="present", choices=["present", "absent"]),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_PURITY_FB:
        module.fail_json(msg="purity_fb sdk is required for this module")
    if module.params["mode"]:
        if not HAS_PYPURECLIENT:
            module.fail_json(msg="py-pure-client sdk is required to support VSO mode")

    state = module.params["state"]
    blade = get_blade(module)
    api_version = blade.api_version.list_versions().versions
    if MIN_REQUIRED_API_VERSION not in api_version:
        module.fail_json(msg="Purity//FB must be upgraded to support this module.")
    if module.params["mode"] and VSO_VERSION not in api_version:
        module.fail_json(msg="VSO mode requires Purity//FB 3.3.3 or higher.")

    bucket = get_bucket(module, blade)
    if not get_s3acc(module, blade):
        module.fail_json(
            msg="Object Store Account {0} does not exist.".format(
                module.params["account"]
            )
        )

    if module.params["eradicate"] and state == "present":
        module.warn("Eradicate flag ignored without state=absent")

    if state == "present" and not bucket:
        create_bucket(module, blade)
    elif state == "present" and bucket and bucket.destroyed:
        recover_bucket(module, blade)
    elif state == "absent" and bucket and not bucket.destroyed:
        delete_bucket(module, blade)
    elif state == "present" and bucket:
        update_bucket(module, blade, bucket)
    elif (
        state == "absent" and bucket and bucket.destroyed and module.params["eradicate"]
    ):
        eradicate_bucket(module, blade)
    elif state == "absent" and not bucket:
        module.exit_json(changed=False)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

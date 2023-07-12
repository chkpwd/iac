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
module: purefb_lifecycle
version_added: '1.4.0'
short_description: Manage FlashBlade object lifecycles
description:
- Manage lifecycles for object buckets
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Create or delete lifecycle rule
    default: present
    type: str
    choices: [ absent, present ]
  bucket:
    description:
    - Bucket the lifecycle rule applies to
    type: str
    required: true
  name:
    description:
    - Name of the lifecycle rule
    type: str
    required: true
  enabled:
    description:
    - State of lifecycle rule
    type: bool
    default: true
  keep_previous_for:
    aliases: [ keep_for ]
    description:
    - Time after which previous versions will be marked expired.
    - Enter as days (d) or weeks (w). Range is 1 - 2147483647 days.
    type: str
  keep_current_for:
    description:
    - Time after which current versions will be marked expired.
    - Enter as days (d) or weeks (w). Range is 1 - 2147483647 days.
    version_added: "1.8.0"
    type: str
  keep_current_until:
    description:
    - Date after which current versions will be marked expired.
    - Enter as date in form YYYY-MM-DD.
    - B(Note:) setting a date in the past will delete ALL objects with
      the value of I(prefix) as they are created.
    version_added: "1.8.0"
    type: str
  abort_uploads_after:
    description:
    - Duration of time after which incomplete multipart uploads will be aborted.
    - Enter as days (d) or weeks (w). Range is 1 - 2147483647 days.
    version_added: "1.8.0"
    type: str
  prefix:
    description:
    - Object key prefix identifying one or more objects in the bucket
    type: str
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Create a lifecycle rule called bar for bucket foo (pre-Purity//FB 3.2.3)
  purestorage.flashblade.purefb_lifecycle:
    name: bar
    bucket: foo
    keep_previous_for: 2d
    prefix: test
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Create a lifecycle rule called bar for bucket foo (post-Purity//FB 3.2.3)
  purestorage.flashblade.purefb_lifecycle:
    name: bar
    bucket: foo
    keep_previous_for: 2d
    keep_current_for: 1w
    abort_uploads_after: 1d
    keep_current_until: 2020-11-23
    prefix: test
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Modify a lifecycle rule (post-Purity//FB 3.2.3)
  purestorage.flashblade.purefb_lifecycle:
    name: bar
    bucket: foo
    keep_previous_for: 10d
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Delete lifecycle rule foo from bucket foo
  purestorage.flashblade.purefb_lifecycle:
    name: foo
    bucket: bar
    state: absent
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
"""

RETURN = r"""
"""

HAS_PURITYFB = True
try:
    from purity_fb import LifecycleRulePost, LifecycleRulePatch, Reference
except ImportError:
    HAS_PURITYFB = False

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
from datetime import datetime


MIN_REQUIRED_API_VERSION = "1.10"
LIFECYCLE_API_VERSION = "2.1"


def _get_bucket(module, blade):
    s3bucket = None
    buckets = blade.buckets.list_buckets()
    for bucket in range(0, len(buckets.items)):
        if buckets.items[bucket].name == module.params["bucket"]:
            s3bucket = buckets.items[bucket]
    return s3bucket


def _convert_date_to_epoch(module):
    try:
        unix_date = datetime.strptime(module.params["keep_current_until"], "%Y-%m-%d")
    except ValueError:
        module.fail_json(msg="Incorrect data format, should be YYYY-MM-DD")
    if unix_date < datetime.utcnow():
        module.warn(
            "This value of `keep_current_until` will permanently delete objects "
            "as they are created. Using this date is not recommended"
        )
    epoch_milliseconds = int((unix_date - datetime(1970, 1, 1)).total_seconds() * 1000)
    return epoch_milliseconds


def _convert_to_millisecs(day):
    try:
        if day[-1:].lower() == "w":
            return int(day[:-1]) * 7 * 86400000
        elif day[-1:].lower() == "d":
            return int(day[:-1]) * 86400000
    except Exception:
        return 0
    return 0


def _findstr(text, match):
    for line in text.splitlines():
        if match in line:
            found = line
    return found


def delete_rule(module, blade):
    """Delete lifecycle rule"""
    changed = True
    if not module.check_mode:
        try:
            blade.lifecycle_rules.delete_lifecycle_rules(
                names=[module.params["bucket"] + "/" + module.params["name"]]
            )
        except Exception:
            module.fail_json(
                msg="Failed to delete lifecycle rule {0} for bucket {1}.".format(
                    module.params["name"], module.params["bucket"]
                )
            )
    module.exit_json(changed=changed)


def create_rule(module, blade, bladev2=None):
    """Create lifecycle policy"""
    changed = True
    if bladev2:
        if (
            not module.params["keep_previous_for"]
            and not module.params["keep_current_until"]
            and not module.params["keep_current_for"]
        ):
            module.fail_json(
                msg="At least one `keep...` parameter is required to create a new lifecycle rule"
            )

    else:
        if not module.params["keep_previous_for"] and not bladev2:
            module.fail_json(
                msg="'keep_previous_for' is required to create a new lifecycle rule"
            )
    if not module.check_mode:
        if not bladev2:
            try:
                attr = LifecycleRulePost(
                    bucket=Reference(name=module.params["bucket"]),
                    rule_id=module.params["name"],
                    keep_previous_version_for=_convert_to_millisecs(
                        module.params["keep_previous_for"]
                    ),
                    prefix=module.params["prefix"],
                )
                blade.lifecycle_rules.create_lifecycle_rules(
                    rule=attr, confirm_date=True
                )
                if not module.params["enabled"]:
                    attr = LifecycleRulePatch()
                    attr.enabled = False
                    blade.lifecycle_rules.update_lifecycle_rules(
                        name=[module.params["bucket"] + "/" + module.params["name"]],
                        rule=attr,
                        confirm_date=True,
                    )
            except Exception:
                module.fail_json(
                    msg="Failed to create lifecycle rule {0} for bucket {1}.".format(
                        module.params["name"], module.params["bucket"]
                    )
                )
        else:
            attr = flashblade.LifecycleRulePost(
                bucket=flashblade.Reference(name=module.params["bucket"]),
                rule_id=module.params["name"],
                keep_previous_version_for=_convert_to_millisecs(
                    module.params["keep_previous_for"]
                ),
                keep_current_version_until=module.params["keep_current_until"],
                keep_current_version_for=_convert_to_millisecs(
                    module.params["keep_current_for"]
                ),
                abort_incomplete_multipart_uploads_after=_convert_to_millisecs(
                    module.params["abort_uploads_after"]
                ),
                prefix=module.params["prefix"],
            )
            if attr.keep_current_version_until:
                res = bladev2.post_lifecycle_rules(rule=attr, confirm_date=True)
            else:
                res = bladev2.post_lifecycle_rules(rule=attr)
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to create lifecycle rule {0} for bucket {1}. Error: {2}".format(
                        module.params["name"],
                        module.params["bucket"],
                        res.errors[0].message,
                    )
                )
            if not module.params["enabled"]:
                attr = flashblade.LifecycleRulePatch(enabled=module.params["enabled"])
                res = bladev2.patch_lifecycle_rules(
                    names=[module.params["bucket"] + "/" + module.params["name"]],
                    lifecycle=attr,
                )
                if res.status_code != 200:
                    module.warn(
                        "Lifecycle Rule {0} did not enable correctly. "
                        "Please chack your FlashBlade".format(module.params["name"])
                    )
    module.exit_json(changed=changed)


def update_rule(module, blade, rule, bladev2=None):
    """Update snapshot policy"""
    changed = False
    if not bladev2:
        current_rule = {
            "prefix": rule.prefix,
            "keep_previous_version_for": rule.keep_previous_version_for,
            "enabled": rule.enabled,
        }
    else:
        current_rule = {
            "prefix": rule.prefix,
            "abort_incomplete_multipart_uploads_after": rule.abort_incomplete_multipart_uploads_after,
            "keep_current_version_for": rule.keep_current_version_for,
            "keep_previous_version_for": rule.keep_previous_version_for,
            "keep_current_version_until": rule.keep_current_version_until,
            "enabled": rule.enabled,
        }
    if not module.params["prefix"]:
        prefix = current_rule["prefix"]
    else:
        prefix = module.params["prefix"]
    if not module.params["keep_previous_for"]:
        keep_previous_for = current_rule["keep_previous_version_for"]
    else:
        keep_previous_for = _convert_to_millisecs(module.params["keep_previous_for"])
    if bladev2:
        if not module.params["keep_current_for"]:
            keep_current_for = current_rule["keep_current_version_for"]
        else:
            keep_current_for = _convert_to_millisecs(module.params["keep_current_for"])
        if not module.params["abort_uploads_after"]:
            abort_uploads_after = current_rule[
                "abort_incomplete_multipart_uploads_after"
            ]
        else:
            abort_uploads_after = _convert_to_millisecs(
                module.params["abort_uploads_after"]
            )
        if not module.params["keep_current_until"]:
            keep_current_until = current_rule["keep_current_version_until"]
        else:
            keep_current_until = module.params["keep_current_until"]
        new_rule = {
            "prefix": prefix,
            "abort_incomplete_multipart_uploads_after": abort_uploads_after,
            "keep_current_version_for": keep_current_for,
            "keep_previous_version_for": keep_previous_for,
            "keep_current_version_until": keep_current_until,
            "enabled": module.params["enabled"],
        }
    else:
        new_rule = {
            "prefix": prefix,
            "keep_previous_version_for": keep_previous_for,
            "enabled": module.params["enabled"],
        }
    if current_rule != new_rule:
        changed = True
        if not module.check_mode:
            if not bladev2:
                try:
                    attr = LifecycleRulePatch(
                        keep_previous_version_for=new_rule["keep_previous_version_for"],
                        prefix=new_rule["prefix"],
                    )
                    attr.enabled = module.params["enabled"]
                    blade.lifecycle_rules.update_lifecycle_rules(
                        names=[module.params["bucket"] + "/" + module.params["name"]],
                        rule=attr,
                        confirm_date=True,
                    )
                except Exception:
                    module.fail_json(
                        msg="Failed to update lifecycle rule {0} for bucket {1}.".format(
                            module.params["name"], module.params["bucket"]
                        )
                    )
            else:
                attr = flashblade.LifecycleRulePatch(
                    keep_previous_version_for=new_rule["keep_previous_version_for"],
                    keep_current_version_for=new_rule["keep_current_version_for"],
                    keep_current_version_until=new_rule["keep_current_version_until"],
                    abort_incomplete_multipart_uploads_after=new_rule[
                        "abort_incomplete_multipart_uploads_after"
                    ],
                    prefix=new_rule["prefix"],
                    enabled=new_rule["enabled"],
                )
                if attr.keep_current_version_until:
                    res = bladev2.patch_lifecycle_rules(
                        names=[module.params["bucket"] + "/" + module.params["name"]],
                        lifecycle=attr,
                        confirm_date=True,
                    )
                else:
                    res = bladev2.patch_lifecycle_rules(
                        names=[module.params["bucket"] + "/" + module.params["name"]],
                        lifecycle=attr,
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to update lifecycle rule {0} for bucket {1}. Error: {2}".format(
                            module.params["name"],
                            module.params["bucket"],
                            res.errors[0].message,
                        )
                    )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="present", choices=["absent", "present"]),
            enabled=dict(type="bool", default=True),
            bucket=dict(type="str", required=True),
            name=dict(type="str", required=True),
            prefix=dict(
                type="str",
            ),
            keep_previous_for=dict(type="str", aliases=["keep_for"]),
            keep_current_for=dict(type="str"),
            keep_current_until=dict(type="str"),
            abort_uploads_after=dict(type="str"),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_PURITYFB:
        module.fail_json(msg="purity_fb sdk is required for this module")

    state = module.params["state"]
    blade = get_blade(module)
    bladev2 = get_system(module)
    versions = blade.api_version.list_versions().versions

    if module.params["keep_previous_for"] and not module.params["keep_previous_for"][
        -1:
    ].lower() in ["w", "d"]:
        module.fail_json(
            msg="'keep_previous_for' format incorrect - specify as 'd' or 'w'"
        )
    if module.params["keep_current_for"] and not module.params["keep_current_for"][
        -1:
    ].lower() in ["w", "d"]:
        module.fail_json(
            msg="'keep_current_for' format incorrect - specify as 'd' or 'w'"
        )
    if module.params["abort_uploads_after"] and not module.params[
        "abort_uploads_after"
    ][-1:].lower() in ["w", "d"]:
        module.fail_json(
            msg="'abort_uploads_after' format incorrect - specify as 'd' or 'w'"
        )

    if MIN_REQUIRED_API_VERSION not in versions:
        module.fail_json(
            msg="Minimum FlashBlade REST version required: {0}".format(
                MIN_REQUIRED_API_VERSION
            )
        )

    if not _get_bucket(module, blade):
        module.fail_json(
            msg="Specified bucket {0} does not exist".format(module.params["bucket"])
        )

    try:
        if LIFECYCLE_API_VERSION not in versions:
            rule = blade.lifecycle_rules.list_lifecycle_rules(
                names=[module.params["bucket"] + "/" + module.params["name"]]
            ).items[0]
        else:
            if module.params["keep_current_until"]:
                module.params["keep_current_until"] = _convert_date_to_epoch(module)
            bladev2 = get_system(module)
            rule = list(
                bladev2.get_lifecycle_rules(
                    names=[module.params["bucket"] + "/" + module.params["name"]]
                ).items
            )[0]
    except Exception:
        rule = None

    if rule and state == "present":
        update_rule(module, blade, rule, bladev2)
    elif state == "present" and not rule:
        create_rule(module, blade, bladev2)
    elif state == "absent" and rule:
        delete_rule(module, blade)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

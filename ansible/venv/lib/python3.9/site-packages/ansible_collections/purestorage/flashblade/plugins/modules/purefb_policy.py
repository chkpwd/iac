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
module: purefb_policy
version_added: '1.0.0'
short_description: Manage FlashBlade policies
description:
- Manage policies for filesystem, file replica links and object store access.
- To update an existing snapshot policy rule, you must first delete the
  original rule and then add the new rule to replace it. Purity's best-fit
  will try to ensure that any required snapshots deleted on the deletion of
  the first rule will be recovered as long replacement rule is added before
  the snapshot eradication period is exceeded (usuually 24 hours).
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Create or delete policy.
    - Copy is applicable only to Object Store Access Policies Rules
    default: present
    type: str
    choices: [ absent, present, copy ]
  target:
    description:
    - Name of policy to copy rule to
    type: str
    version_added: "1.9.0"
  target_rule:
    description:
    - Name of the rule to copy the exisitng rule to.
    - If not defined the existing rule name is used.
    type: str
    version_added: "1.9.0"
  policy_type:
    description:
    - Type of policy
    default: snapshot
    type: str
    choices: [ snapshot, access, nfs ]
    version_added: "1.9.0"
  account:
    description:
    - Name of Object Store account policy applies to.
    - B(Special Case) I(pure policy) is used for the system-wide S3 policies
    type: str
    version_added: "1.9.0"
  rule:
    description:
    - Name of the rule for the Object Store Access Policy
    - Rules in system wide policies cannot be deleted or modified
    type: str
    version_added: "1.9.0"
  effect:
    description:
    - Allow S3 requests that match all of the I(actions) item selected.
      Rules are additive.
    type: str
    default: allow
    choices: [ allow ]
    version_added: "1.9.0"
  actions:
    description:
    - List of permissions to grant.
    - System-wide policy rules cannot be deleted or modified
    type: list
    elements: str
    choices:
      - s3:*
      - s3:AbortMultipartUpload
      - s3:CreateBucket
      - s3:DeleteBucket
      - s3:DeleteObject
      - s3:DeleteObjectVersion
      - s3:ExtendSafemodeRetentionPeriod
      - s3:GetBucketAcl
      - s3:GetBucketLocation
      - s3:GetBucketVersioning
      - s3:GetLifecycleConfiguration
      - s3:GetObject
      - s3:GetObjectAcl
      - s3:GetObjectVersion
      - s3:ListAllMyBuckets
      - s3:ListBucket
      - s3:ListBucketMultipartUploads
      - s3:ListBucketVersions
      - s3:ListMultipartUploadParts
      - s3:PutBucketVersioning
      - s3:PutLifecycleConfiguration
      - s3:PutObject
    version_added: "1.9.0"
  object_resources:
    description:
    - List of bucket names and object paths, with a wildcard (*) to
      specify objects in a bucket; e.g., bucket1, bucket1/*, bucket2,
      bucket2/*.
    - System-wide policy rules cannot be deleted or modified
    type: list
    elements: str
    version_added: "1.9.0"
  source_ips:
    description:
    - List of IPs and subnets from which this rule should allow requests;
      e.g., 10.20.30.40, 10.20.30.0/24, 2001:DB8:1234:5678::/64.
    - System-wide policy rules cannot be deleted or modified
    type: list
    elements: str
    version_added: "1.9.0"
  s3_prefixes:
    description:
    - List of 'folders' (object key prefixes) for which object listings
      may be requested.
    - System-wide policy rules cannot be deleted or modified
    type: list
    elements: str
    version_added: "1.9.0"
  s3_delimiters:
    description:
    - List of delimiter characters allowed in object list requests.
    - Grants permissions to list 'folder names' (prefixes ending in a
      delimiter) instead of object keys.
    - System-wide policy rules cannot be deleted or modified
    type: list
    elements: str
    version_added: "1.9.0"
  ignore_enforcement:
    description:
    - Certain combinations of actions and other rule elements are inherently
      ignored if specified together in a rule.
    - If set to true, operations which attempt to set these combinations will fail.
    - If set to false, such operations will instead be allowed.
    type: bool
    default: true
    version_added: "1.9.0"
  user:
    description:
    - User in the I(account) that the policy is granted to.
    type: str
    version_added: "1.9.0"
  force_delete:
    description:
    - Force the deletion of a Object Store Access Policy is this
      has attached users.
    - WARNING This can have undesired side-effects.
    - System-wide policies cannot be deleted
    type: bool
    default: false
    version_added: "1.9.0"
  name:
    description:
    - Name of the policy
    type: str
  enabled:
    description:
    - State of policy
    type: bool
    default: true
  every:
    description:
    - Interval between snapshots in seconds
    - Range available 300 - 31536000 (equates to 5m to 365d)
    type: int
  keep_for:
    description:
    - How long to keep snapshots for
    - Range available 300 - 31536000 (equates to 5m to 365d)
    - Must not be set less than I(every)
    type: int
  at:
    description:
    - Provide a time in 12-hour AM/PM format, eg. 11AM
    type: str
  timezone:
    description:
    - Time Zone used for the I(at) parameter
    - If not provided, the module will attempt to get the current local timezone from the server
    type: str
  filesystem:
    description:
    - List of filesystems to add to a policy on creation
    - To amend policy members use the I(purestorage.flashblade.purefb_fs) module
    type: list
    elements: str
  replica_link:
    description:
    - List of filesystem replica links to add to a policy on creation
    - To amend policy members use the I(purestorage.flashblade.purefb_fs_replica) module
    type: list
    elements: str
  access:
    description:
    - Specifies access control for the export policy rule
    type: str
    choices: [ root-squash, all-squash, no-squash ]
    default: root-squash
    version_added: "1.9.0"
  anonuid:
    description:
    - Any user whose UID is affected by an I(access) of `root_squash` or `all_squash`
      will have their UID mapped to anonuid.
      The defaultis null, which means 65534.
      Use "" to clear.
    type: str
    version_added: "1.9.0"
  anongid:
    description:
    - Any user whose GID is affected by an I(access) of `root_squash` or `all_squash`
      will have their GID mapped to anongid.
      The default anongid is null, which means 65534.
      Use "" to clear.
    type: str
    version_added: "1.9.0"
  atime:
    description:
    - After a read operation has occurred, the inode access time is updated only if any
      of the following conditions is true; the previous access time is less than the
      inode modify time, the previous access time is less than the inode change time,
      or the previous access time is more than 24 hours ago.
    - If set to false, disables the update of inode access times after read operations.
    type: bool
    default: true
    version_added: "1.9.0"
  client:
    description:
    - Specifies the clients that will be permitted to access the export.
    - Accepted notation is a single IP address, subnet in CIDR notation, netgroup, or
      anonymous (*).
    type: str
    default: "*"
    version_added: "1.9.0"
  fileid_32bit:
    description:
    - Whether the file id is 32 bits or not.
    type: bool
    default: false
    version_added: "1.9.0"
  permission:
    description:
    - Specifies which read-write client access permissions are allowed for the export.
    type: str
    choices: [ rw, ro ]
    default: ro
    version_added: "1.9.0"
  secure:
    description:
    - If true, this prevents NFS access to client connections coming from non-reserved ports.
    - If false, allows NFS access to client connections coming from non-reserved ports.
    - Applies to NFSv3, NFSv4.1, and auxiliary protocols MOUNT and NLM.
    type: bool
    default: false
    version_added: "1.9.0"
  security:
    description:
    - The security flavors to use for accessing files on this mount point.
    - If the server does not support the requested flavor, the mount operation fails.
    - I(sys) trusts the client to specify users identity.
    - I(krb) provides cryptographic proof of a users identity in each RPC request.
    - I(krb5i) adds integrity checking to krb5, to ensure the data has not been tampered with.
    - I(krb5p) adds integrity checking and encryption to krb5.
    type: list
    elements: str
    choices: [ sys, krb5, krb5i, krb5p ]
    default: sys
    version_added: "1.9.0"
  before_rule:
    description:
    - The index of the client rule to insert or move a client rule before.
    type: int
    version_added: "1.9.0"
  rename:
    description:
    - New name for export policy
    - Only applies to NFS export policies
    type: str
    version_added: "1.10.0"
  destroy_snapshots:
    description:
    - This parameter must be set to true in order to modify a policy such that local or remote snapshots would be destroyed.
    type: bool
    version_added: '1.11.0'
    default: false
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Create a simple snapshot policy with no rules
  purestorage.flashblade.purefb_policy:
    name: test_policy
    policy_type: snapshot
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Create a snapshot policy and connect to existing filesystems and filesystem replica links
  purestorage.flashblade.purefb_policy:
    name: test_policy_with_members
    policy_type: snapshot
    filesystem:
    - fs1
    - fs2
    replica_link:
    - rl1
    - rl2
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Create a snapshot policy with rules
  purestorage.flashblade.purefb_policy:
    name: test_policy2
    policy_type: snapshot
    at: 11AM
    keep_for: 86400
    every: 86400
    timezone: Asia/Shanghai
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Delete a snapshot policy
  purestorage.flashblade.purefb_policy:
    name: test_policy
    policy_type: snapshot
    state: absent
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Create an empty object store access policy
  purestorage.flashblade.purefb_policy:
    name: test_os_policy
    account: test
    policy_type: access
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Create an empty object store access policy and assign user
  purestorage.flashblade.purefb_policy:
    name: test_os_policy
    account: test
    policy_type: access
    user: fred
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Create a object store access policy with simple rule
  purestorage.flashblade.purefb_policy:
    name: test_os_policy_rule
    policy_type: access
    account: test
    rule: rule1
    actions: "s3:*"
    object_resources: "*"
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Create an empty NFS export policy
  purestorage.flashblade.purefb_policy:
    name: test_nfs_export
    policy_type: nfs
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Create an NFS export policy with a client rule
  purestorage.flashblade.purefb_policy:
    name: test_nfs_export
    policy_type: nfs
    atime: true
    client: "10.0.1.0/24"
    secure: true
    security: [sys, krb5]
    permission: rw
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Create a new rule for an existing NFS export policy
  purestorage.flashblade.purefb_policy:
    name: test_nfs_export
    policy_type: nfs
    atime: true
    client: "10.0.2.0/24"
    security: sys
    permission: ro
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Delete a client rule from an NFS export policy
  purestorage.flashblade.purefb_policy:
    name: test_nfs_export
    client: "10.0.1.0/24"
    policy_type: nfs
    state: absent
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Delete an NFS export policy and all associated rules
  purestorage.flashblade.purefb_policy:
    name: test_nfs_export
    state: absent
    policy_type: nfs
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Delete a rule from an object store access policy
  purestorage.flashblade.purefb_policy:
    name: test_os_policy_rule
    account: test
    policy_type: access
    rule: rule1
    state: absent
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Delete a user from an object store access policy
  purestorage.flashblade.purefb_policy:
    name: test_os_policy_rule
    account: test
    user: fred
    policy_type: access
    state: absent
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Delete an object store access policy with attached users (USE WITH CAUTION)
  purestorage.flashblade.purefb_policy:
    name: test_os_policy_rule
    account: test
    policy_type: access
    force_delete: true
    state: absent
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Delete an object store access policy with no attached users
  purestorage.flashblade.purefb_policy:
    name: test_os_policy_rule
    account: test
    policy_type: access
    state: absent
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Copy an object store access policy rule to another exisitng policy
  purestorage.flashblade.purefb_policy:
    name: test_os_policy_rule
    policy_type: access
    account: test
    target: "account2/anotherpolicy"
    target_rule: new_rule1
    state: copy
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name:  Rename an NFS Export Policy
  purestorage.flashblade.purefb_policy:
    name: old_name
    policy_type: nfs
    rename: new_name
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
"""

RETURN = r"""
"""

HAS_PURITYFB = True
try:
    from purity_fb import Policy, PolicyRule, PolicyPatch
except ImportError:
    HAS_PURITYFB = False

HAS_PYPURECLIENT = True
try:
    from pypureclient.flashblade import (
        PolicyRuleObjectAccessCondition,
        PolicyRuleObjectAccessPost,
        PolicyRuleObjectAccess,
        NfsExportPolicy,
        NfsExportPolicyRule,
        Policy,
        PolicyRule,
    )
except ImportError:
    HAS_PYPURECLIENT = False

HAS_PYTZ = True
try:
    import pytz
except ImportError:
    HAS_PYTX = False

import os
import re
import platform

from ansible.module_utils.common.process import get_bin_path
from ansible.module_utils.facts.utils import get_file_content
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_blade,
    get_system,
    purefb_argument_spec,
)


MIN_REQUIRED_API_VERSION = "1.9"
SNAPSHOT_POLICY_API_VERSION = "2.1"
ACCESS_POLICY_API_VERSION = "2.2"
NFS_POLICY_API_VERSION = "2.3"
NFS_RENAME_API_VERSION = "2.4"


def _convert_to_millisecs(hour):
    if hour[-2:] == "AM" and hour[:2] == "12":
        return 0
    elif hour[-2:] == "AM":
        return int(hour[:-2]) * 3600000
    elif hour[-2:] == "PM" and hour[:2] == "12":
        return 43200000
    return (int(hour[:-2]) + 12) * 3600000


def _findstr(text, match):
    for line in text.splitlines():
        if match in line:
            found = line
    return found


def _get_local_tz(module, timezone="UTC"):
    """
    We will attempt to get the local timezone of the server running the module and use that.
    If we can't get the timezone then we will set the default to be UTC

    Linnux has been tested and other opersting systems should be OK.
    Failures cause assumption of UTC

    Windows is not supported and will assume UTC
    """
    if platform.system() == "Linux":
        timedatectl = get_bin_path("timedatectl")
        if timedatectl is not None:
            rcode, stdout, stderr = module.run_command(timedatectl)
            if rcode == 0 and stdout:
                line = _findstr(stdout, "Time zone")
                full_tz = line.split(":", 1)[1].rstrip()
                timezone = full_tz.split()[0]
                return timezone
            else:
                module.warn("Incorrect timedatectl output. Timezone will be set to UTC")
        else:
            if os.path.exists("/etc/timezone"):
                timezone = get_file_content("/etc/timezone")
            else:
                module.warn("Could not find /etc/timezone. Assuming UTC")

    elif platform.system() == "SunOS":
        if os.path.exists("/etc/default/init"):
            for line in get_file_content("/etc/default/init", "").splitlines():
                if line.startswith("TZ="):
                    timezone = line.split("=", 1)[1]
                    return timezone
        else:
            module.warn("Could not find /etc/default/init. Assuming UTC")

    elif re.match("^Darwin", platform.platform()):
        systemsetup = get_bin_path("systemsetup")
        if systemsetup is not None:
            rcode, stdout, stderr = module.execute(systemsetup, "-gettimezone")
            if rcode == 0 and stdout:
                timezone = stdout.split(":", 1)[1].lstrip()
            else:
                module.warn("Could not run systemsetup. Assuming UTC")
        else:
            module.warn("Could not find systemsetup. Assuming UTC")

    elif re.match("^(Free|Net|Open)BSD", platform.platform()):
        if os.path.exists("/etc/timezone"):
            timezone = get_file_content("/etc/timezone")
        else:
            module.warn("Could not find /etc/timezone. Assuming UTC")

    elif platform.system() == "AIX":
        aix_oslevel = int(platform.version() + platform.release())
        if aix_oslevel >= 61:
            if os.path.exists("/etc/environment"):
                for line in get_file_content("/etc/environment", "").splitlines():
                    if line.startswith("TZ="):
                        timezone = line.split("=", 1)[1]
                        return timezone
            else:
                module.warn("Could not find /etc/environment. Assuming UTC")
        else:
            module.warn(
                "Cannot determine timezone when AIX os level < 61. Assuming UTC"
            )

    else:
        module.warn("Could not find /etc/timezone. Assuming UTC")

    return timezone


def delete_nfs_policy(module, blade):
    """Delete NFS Export Policy, or Rule

    If client is provided then delete the client rule if it exists.
    """

    changed = False
    policy_delete = True
    if module.params["client"]:
        policy_delete = False
        res = blade.get_nfs_export_policies_rules(
            policy_names=[module.params["name"]],
            filter="client='" + module.params["client"] + "'",
        )
        if res.status_code == 200:
            if res.total_item_count == 0:
                pass
            elif res.total_item_count == 1:
                rule = list(res.items)[0]
                if module.params["client"] == rule.client:
                    changed = True
                    if not module.check_mode:
                        res = blade.delete_nfs_export_policies_rules(names=[rule.name])
                        if res.status_code != 200:
                            module.fail_json(
                                msg="Failed to delete rule for client {0} in policy {1}. "
                                "Error: {2}".format(
                                    module.params["client"],
                                    module.params["name"],
                                    res.errors[0].message,
                                )
                            )
            else:
                rules = list(res.items)
                for cli in range(0, len(rules)):
                    if rules[cli].client == "*":
                        changed = True
                        if not module.check_mode:
                            res = blade.delete_nfs_export_policies_rules(
                                names=[rules[cli].name]
                            )
                            if res.status_code != 200:
                                module.fail_json(
                                    msg="Failed to delete rule for client {0} in policy {1}. "
                                    "Error: {2}".format(
                                        module.params["client"],
                                        module.params["name"],
                                        res.errors[0].message,
                                    )
                                )
    if policy_delete:
        changed = True
        if not module.check_mode:
            res = blade.delete_nfs_export_policies(names=[module.params["name"]])
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to delete export policy {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def rename_nfs_policy(module, blade):
    """Rename NFS Export Policy"""

    changed = True
    if not module.check_mode:
        res = blade.patch_nfs_export_policies(
            names=[module.params["name"]],
            policy=NfsExportPolicy(name=module.params["rename"]),
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to rename NFS export policy {0} to {1}. Error: {2}".format(
                    module.params["name"],
                    module.params["rename"],
                    res.errors[0].message,
                )
            )
        module.exit_json(changed=changed)


def update_nfs_policy(module, blade):
    """Update NFS Export Policy Rule"""

    changed = False
    if module.params["client"]:
        current_policy_rule = blade.get_nfs_export_policies_rules(
            policy_names=[module.params["name"]],
            filter="client='" + module.params["client"] + "'",
        )
        if (
            current_policy_rule.status_code == 200
            and current_policy_rule.total_item_count == 0
        ):
            rule = NfsExportPolicyRule(
                client=module.params["client"],
                permission=module.params["permission"],
                access=module.params["access"],
                anonuid=module.params["anonuid"],
                anongid=module.params["anongid"],
                fileid_32bit=module.params["fileid_32bit"],
                atime=module.params["atime"],
                secure=module.params["secure"],
                security=module.params["security"],
            )
            changed = True
            if not module.check_mode:
                if module.params["before_rule"]:
                    before_name = (
                        module.params["name"] + "." + str(module.params["before_rule"])
                    )
                    res = blade.post_nfs_export_policies_rules(
                        policy_names=[module.params["name"]],
                        rule=rule,
                        before_rule_name=before_name,
                    )
                else:
                    res = blade.post_nfs_export_policies_rules(
                        policy_names=[module.params["name"]],
                        rule=rule,
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to create rule for client {0} "
                        "in export policy {1}. Error: {2}".format(
                            module.params["client"],
                            module.params["name"],
                            res.errors[0].message,
                        )
                    )
        else:
            rules = list(current_policy_rule.items)
            cli_count = None
            done = False
            if module.params["client"] == "*":
                for cli in range(0, len(rules)):
                    if rules[cli].client == "*":
                        cli_count = cli
                if not cli_count:
                    rule = NfsExportPolicyRule(
                        client=module.params["client"],
                        permission=module.params["permission"],
                        access=module.params["access"],
                        anonuid=module.params["anonuid"],
                        anongid=module.params["anongid"],
                        fileid_32bit=module.params["fileid_32bit"],
                        atime=module.params["atime"],
                        secure=module.params["secure"],
                        security=module.params["security"],
                    )
                    done = True
                    changed = True
                    if not module.check_mode:
                        if module.params["before_rule"]:
                            res = blade.post_nfs_export_policies_rules(
                                policy_names=[module.params["name"]],
                                rule=rule,
                                before_rule_name=(
                                    module.params["name"]
                                    + "."
                                    + str(module.params["before_rule"]),
                                ),
                            )
                        else:
                            res = blade.post_nfs_export_policies_rules(
                                policy_names=[module.params["name"]],
                                rule=rule,
                            )
                        if res.status_code != 200:
                            module.fail_json(
                                msg="Failed to create rule for "
                                "client {0} in export policy {1}. Error: {2}".format(
                                    module.params["client"],
                                    module.params["name"],
                                    res.errors[0].message,
                                )
                            )
            if not done:
                old_policy_rule = rules[0]
                current_rule = {
                    "anongid": getattr(old_policy_rule, "anongid", None),
                    "anonuid": getattr(old_policy_rule, "anonuid", None),
                    "atime": old_policy_rule.atime,
                    "client": sorted(old_policy_rule.client),
                    "fileid_32bit": old_policy_rule.fileid_32bit,
                    "permission": sorted(old_policy_rule.permission),
                    "secure": old_policy_rule.secure,
                    "security": sorted(old_policy_rule.security),
                }
                if module.params["permission"]:
                    new_permission = sorted(module.params["permission"])
                else:
                    new_permission = sorted(current_rule["permission"])
                if module.params["client"]:
                    new_client = sorted(module.params["client"])
                else:
                    new_client = sorted(current_rule["client"])
                if module.params["security"]:
                    new_security = sorted(module.params["security"])
                else:
                    new_security = sorted(current_rule["security"])
                if module.params["anongid"]:
                    new_anongid = module.params["anongid"]
                else:
                    new_anongid = current_rule["anongid"]
                if module.params["anonuid"]:
                    new_anonuid = module.params["anonuid"]
                else:
                    new_anonuid = current_rule["anonuid"]
                if module.params["atime"] != current_rule["atime"]:
                    new_atime = module.params["atime"]
                else:
                    new_atime = current_rule["atime"]
                if module.params["secure"] != current_rule["secure"]:
                    new_secure = module.params["secure"]
                else:
                    new_secure = current_rule["secure"]
                if module.params["fileid_32bit"] != current_rule["fileid_32bit"]:
                    new_fileid_32bit = module.params["fileid_32bit"]
                else:
                    new_fileid_32bit = current_rule["fileid_32bit"]
                new_rule = {
                    "anongid": new_anongid,
                    "anonuid": new_anonuid,
                    "atime": new_atime,
                    "client": new_client,
                    "fileid_32bit": new_fileid_32bit,
                    "permission": new_permission,
                    "secure": new_secure,
                    "security": new_security,
                }
                if current_rule != new_rule:
                    changed = True
                    if not module.check_mode:
                        rule = NfsExportPolicyRule(
                            client=module.params["client"],
                            permission=module.params["permission"],
                            access=module.params["access"],
                            anonuid=module.params["anonuid"],
                            anongid=module.params["anongid"],
                            fileid_32bit=module.params["fileid_32bit"],
                            atime=module.params["atime"],
                            secure=module.params["secure"],
                            security=module.params["security"],
                        )
                        res = blade.patch_nfs_export_policies_rules(
                            names=[
                                module.params["name"] + "." + str(old_policy_rule.index)
                            ],
                            rule=rule,
                        )
                        if res.status_code != 200:
                            module.fail_json(
                                msg="Failed to update NFS export rule {0}. Error: {1}".format(
                                    module.params["name"]
                                    + "."
                                    + str(old_policy_rule.index),
                                    res.errors[0].message,
                                )
                            )
                if (
                    module.params["before_rule"]
                    and module.params["before_rule"] != old_policy_rule.index
                ):
                    changed = True
                    if not module.check_mode:
                        before_name = (
                            module.params["name"]
                            + "."
                            + str(module.params["before_rule"])
                        )
                        res = blade.patch_nfs_export_policies_rules(
                            names=[
                                module.params["name"] + "." + str(old_policy_rule.index)
                            ],
                            rule=NfsExportPolicyRule(),
                            before_rule_name=before_name,
                        )
                        if res.status_code != 200:
                            module.fail_json(
                                msg="Failed to move NFS export rule {0}. Error: {1}".format(
                                    module.params["name"]
                                    + "."
                                    + str(old_policy_rule.index),
                                    res.errors[0].message,
                                )
                            )
    current_policy = list(
        blade.get_nfs_export_policies(names=[module.params["name"]]).items
    )[0]
    if current_policy.enabled != module.params["enabled"]:
        changed = True
        if not module.check_mode:
            res = blade.patch_nfs_export_policies(
                policy=NfsExportPolicy(enabled=module.params["enabled"]),
                names=[module.params["name"]],
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to change state of nfs export policy {0}.Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def create_nfs_policy(module, blade):
    """Create NFS Export Policy"""
    changed = True
    if not module.check_mode:
        res = blade.post_nfs_export_policies(names=[module.params["name"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to create nfs export policy {0}.Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
        if not module.params["enabled"]:
            res = blade.patch_nfs_export_policies(
                policy=NfsExportPolicy(enabled=False), names=[module.params["name"]]
            )
            if res.status_code != 200:
                blade.delete_nfs_export_policies(names=[module.params["name"]])
                module.fail_json(
                    msg="Failed to create nfs export policy {0}.Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
        if not module.params["client"]:
            module.fail_json(msg="client is required to create a new rule")
        else:
            rule = NfsExportPolicyRule(
                client=module.params["client"],
                permission=module.params["permission"],
                access=module.params["access"],
                anonuid=module.params["anonuid"],
                anongid=module.params["anongid"],
                fileid_32bit=module.params["fileid_32bit"],
                atime=module.params["atime"],
                secure=module.params["secure"],
                security=module.params["security"],
            )
            res = blade.post_nfs_export_policies_rules(
                policy_names=[module.params["name"]],
                rule=rule,
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to rule for policy {0}. Error: {1}".format(
                        module.params["name"],
                        res.errors[0].message,
                    )
                )
    module.exit_json(changed=changed)


def delete_os_policy(module, blade):
    """Delete Object Store Access Policy, Rule, or User

    If rule is provided then delete the rule if it exists.
    If user is provided then remove grant from user if granted.
    If no user or rule provided delete the whole policy.
    Cannot delete a policy with attached users, so delete all users
    if the force_delete option is selected.
    """

    changed = False
    policy_name = module.params["account"] + "/" + module.params["name"]
    policy_delete = True
    if module.params["rule"]:
        policy_delete = False
        res = blade.get_object_store_access_policies_rules(
            policy_names=[policy_name], names=[module.params["rule"]]
        )
        if res.status_code == 200 and res.total_item_count != 0:
            changed = True
            if not module.check_mode:
                res = blade.delete_object_store_access_policies_object_store_rules(
                    policy_names=[policy_name], names=[module.params["rule"]]
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to delete users from policy {0}. Error: {1} - {2}".format(
                            policy_name, res.errors[0].context, res.errors[0].message
                        )
                    )

    if module.params["user"]:
        member_name = module.params["account"] + "/" + module.params["user"]
        policy_delete = False
        res = blade.get_object_store_access_policies_object_store_users(
            policy_names=[policy_name], member_names=[member_name]
        )
        if res.status_code == 200 and res.total_item_count != 0:
            changed = True
            if not module.check_mode:
                member_name = module.params["account"] + "/" + module.params["user"]
                res = blade.delete_object_store_access_policies_object_store_users(
                    policy_names=[policy_name], member_names=[member_name]
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to delete users from policy {0}. Error: {1} - {2}".format(
                            policy_name, res.errors[0].context, res.errors[0].message
                        )
                    )

    if policy_delete:
        if module.params["account"].lower() == "pure:policy":
            module.fail_json(msg="System-Wide policies cannot be deleted.")
        policy_users = list(
            blade.get_object_store_access_policies_object_store_users(
                policy_names=[policy_name]
            ).items
        )
        if len(policy_users) == 0:
            changed = True
            if not module.check_mode:
                res = blade.delete_object_store_access_policies(names=[policy_name])
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to delete policy {0}. Error: {1}".format(
                            policy_name, res.errors[0].message
                        )
                    )
        else:
            if module.params["force_delete"]:
                changed = True
                if not module.check_mode:
                    for user in range(0, len(policy_users)):
                        res = blade.delete_object_store_access_policies_object_store_users(
                            member_names=[policy_users[user].member.name],
                            policy_names=[policy_name],
                        )
                        if res.status_code != 200:
                            module.fail_json(
                                msg="Failed to delete user {0} from policy {1}, "
                                "Error: {2}".format(
                                    policy_users[user].member,
                                    policy_name,
                                    res.errors[0].message,
                                )
                            )
                    res = blade.delete_object_store_access_policies(names=[policy_name])
                    if res.status_code != 200:
                        module.fail_json(
                            msg="Failed to delete policy {0}. Error: {1}".format(
                                policy_name, res.errors[0].message
                            )
                        )
            else:
                module.fail_json(
                    msg="Policy {0} cannot be deleted with connected users".format(
                        policy_name
                    )
                )
    module.exit_json(changed=changed)


def create_os_policy(module, blade):
    """Create Object Store Access Policy"""
    changed = True
    policy_name = module.params["account"] + "/" + module.params["name"]
    if not module.check_mode:
        res = blade.post_object_store_access_policies(names=[policy_name])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to create access policy {0}.".format(policy_name)
            )
        if module.params["rule"]:
            if not module.params["actions"] or not module.params["object_resources"]:
                module.fail_json(
                    msg="Parameters `actions` and `object_resources` "
                    "are required to create a new rule"
                )
            conditions = PolicyRuleObjectAccessCondition(
                source_ips=module.params["source_ips"],
                s3_delimiters=module.params["s3_delimiters"],
                s3_prefixes=module.params["s3_prefixes"],
            )
            rule = PolicyRuleObjectAccessPost(
                actions=module.params["actions"],
                resources=module.params["object_resources"],
                conditions=conditions,
            )
            res = blade.post_object_store_access_policies_rules(
                policy_names=policy_name,
                names=[module.params["rule"]],
                enforce_action_restrictions=module.params["ignore_enforcement"],
                rule=rule,
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to create rule {0} to policy {1}. Error: {2}".format(
                        module.params["rule"], policy_name, res.errors[0].message
                    )
                )
        if module.params["user"]:
            member_name = module.params["account"] + "/" + module.params["user"]
            res = blade.post_object_store_access_policies_object_store_users(
                member_names=[member_name], policy_names=[policy_name]
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to add users to policy {0}. Error: {1} - {2}".format(
                        policy_name, res.errors[0].context, res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def update_os_policy(module, blade):
    """Update Object Store Access Policy"""
    changed = False
    policy_name = module.params["account"] + "/" + module.params["name"]
    if module.params["rule"]:
        current_policy_rule = blade.get_object_store_access_policies_rules(
            policy_names=[policy_name], names=[module.params["rule"]]
        )
        if current_policy_rule.status_code != 200:
            conditions = PolicyRuleObjectAccessCondition(
                source_ips=module.params["source_ips"],
                s3_delimiters=module.params["s3_delimiters"],
                s3_prefixes=module.params["s3_prefixes"],
            )
            rule = PolicyRuleObjectAccessPost(
                actions=module.params["actions"],
                resources=module.params["object_resources"],
                conditions=conditions,
            )
            res = blade.post_object_store_access_policies_rules(
                policy_names=policy_name,
                names=[module.params["rule"]],
                enforce_action_restrictions=module.params["ignore_enforcement"],
                rule=rule,
            )
        else:
            old_policy_rule = list(current_policy_rule.items)[0]
            current_rule = {
                "actions": old_policy_rule.actions,
                "resources": old_policy_rule.resources,
                "ips": getattr(old_policy_rule.conditions, "source_ips", None),
                "prefixes": getattr(old_policy_rule.conditions, "s3_prefixes", None),
                "delimiters": getattr(
                    old_policy_rule.conditions, "s3_delimiters", None
                ),
            }
            if module.params["actions"]:
                new_actions = sorted(module.params["actions"])
            else:
                new_actions = sorted(current_rule["actions"])
            if module.params["object_resources"]:
                new_resources = sorted(module.params["object_resources"])
            else:
                new_resources = sorted(current_rule["resources"])
            if module.params["s3_prefixes"]:
                new_prefixes = sorted(module.params["s3_prefixes"])
            elif current_rule["prefixes"]:
                new_prefixes = sorted(current_rule["prefixes"])
            else:
                new_prefixes = None
            if module.params["s3_delimiters"]:
                new_delimiters = sorted(module.params["s3_delimiters"])
            elif current_rule["delimiters"]:
                new_delimiters = sorted(current_rule["delimiters"])
            else:
                new_delimiters = None
            if module.params["source_ips"]:
                new_ips = sorted(module.params["source_ips"])
            elif current_rule["ips"]:
                new_ips = sorted(current_rule["source_ips"])
            else:
                new_ips = None
            new_rule = {
                "actions": new_actions,
                "resources": new_resources,
                "ips": new_ips,
                "prefixes": new_prefixes,
                "delimiters": new_delimiters,
            }
            if current_rule != new_rule:
                changed = True
                if not module.check_mode:
                    conditions = PolicyRuleObjectAccessCondition(
                        source_ips=new_rule["ips"],
                        s3_prefixes=new_rule["prefixes"],
                        s3_delimiters=new_rule["delimiters"],
                    )
                    rule = PolicyRuleObjectAccess(
                        actions=new_rule["actions"],
                        resources=new_rule["resources"],
                        conditions=conditions,
                    )
                    res = blade.patch_object_store_access_policies_rules(
                        policy_names=[policy_name],
                        names=[module.params["rule"]],
                        rule=rule,
                        enforce_action_restrictions=module.params["ignore_enforcement"],
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to update rule {0} in policy {1}. Error: {2}".format(
                            module.params["rule"], policy_name, res.errors[0].message
                        )
                    )
    if module.params["user"]:
        member_name = module.params["account"] + "/" + module.params["user"]
        res = blade.get_object_store_access_policies_object_store_users(
            policy_names=[policy_name], member_names=[member_name]
        )
        if res.status_code != 200 or (
            res.status_code == 200 and res.total_item_count == 0
        ):
            changed = True
            if not module.check_mode:
                res = blade.post_object_store_access_policies_object_store_users(
                    member_names=[member_name], policy_names=[policy_name]
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to add user {0} to policy {1}. Error: {2}".format(
                            member_name, policy_name, res.errors[0].message
                        )
                    )
    module.exit_json(changed=changed)


def copy_os_policy_rule(module, blade):
    """Copy an existing policy rule to a new policy"""
    changed = True
    policy_name = module.params["account"] + "/" + module.params["name"]
    if not module.params["target_rule"]:
        module.params["target_rule"] = module.params["rule"]
    if (
        blade.get_object_store_access_policies_rules(
            policy_names=[module.params["target"]], names=[module.params["target_rule"]]
        ).status_code
        == 200
    ):
        module.fail_json(
            msg="Target rule {0} already exists in policy {1}".format(
                module.params["target_rule"], policy_name
            )
        )
    current_rule = list(
        blade.get_object_store_access_policies_rules(
            policy_names=[policy_name], names=[module.params["rule"]]
        ).items
    )[0]
    if not module.check_mode:
        conditions = PolicyRuleObjectAccessCondition(
            source_ips=current_rule.conditions.source_ips,
            s3_delimiters=current_rule.conditions.s3_delimiters,
            s3_prefixes=current_rule.conditions.s3_prefixes,
        )
        rule = PolicyRuleObjectAccessPost(
            actions=current_rule.actions,
            resources=current_rule.resources,
            conditions=conditions,
        )
        res = blade.post_object_store_access_policies_rules(
            policy_names=module.params["target"],
            names=[module.params["target_rule"]],
            enforce_action_restrictions=module.params["ignore_enforcement"],
            rule=rule,
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to copy rule {0} from policy {1} to policy {2}. "
                "Error: {3}".format(
                    module.params["rule"],
                    policy_name,
                    module.params["target"],
                    res.errors[0].message,
                )
            )
    module.exit_json(changed=changed)


def delete_policy(module, blade):
    """Delete policy"""
    changed = True
    if not module.check_mode:
        try:
            blade.policies.delete_policies(names=[module.params["name"]])
        except Exception:
            module.fail_json(
                msg="Failed to delete policy {0}.".format(module.params["name"])
            )
    module.exit_json(changed=changed)


def delete_snap_policy(module, blade):
    """Delete REST 2 snapshot policy

    If any rule parameters are provided then delete any rules that match
    all of the parameters provided.
    If no rule parameters are provided delete the entire policy
    """

    changed = False
    rule_delete = False
    if (
        module.params["at"]
        or module.params["every"]
        or module.params["timezone"]
        or module.params["keep_for"]
    ):
        rule_delete = True
    if rule_delete:
        current_rules = list(blade.get_policies(names=[module.params["name"]]).items)[
            0
        ].rules
        for rule in range(0, len(current_rules)):
            current_rule = {
                "at": current_rules[rule].at,
                "every": current_rules[rule].every,
                "keep_for": current_rules[rule].keep_for,
                "time_zone": current_rules[rule].time_zone,
            }
            if not module.params["at"]:
                delete_at = current_rules[rule].at
            else:
                delete_at = _convert_to_millisecs(module.params["at"])
            if module.params["keep_for"]:
                delete_keep_for = module.params["keep_for"]
            else:
                delete_keep_for = int(current_rules[rule].keep_for / 1000)
            if module.params["every"]:
                delete_every = module.params["every"]
            else:
                delete_every = int(current_rules[rule].every / 1000)
            if not module.params["timezone"]:
                delete_tz = current_rules[rule].time_zone
            else:
                delete_tz = module.params["timezone"]
            delete_rule = {
                "at": delete_at,
                "every": delete_every * 1000,
                "keep_for": delete_keep_for * 1000,
                "time_zone": delete_tz,
            }
            if current_rule == delete_rule:
                changed = True
                attr = PolicyPatch(remove_rules=[delete_rule])
                if not module.check_mode:
                    res = blade.patch_policies(
                        destroy_snapshots=module.params["destroy_snapshots"],
                        names=[module.params["name"]],
                        policy=attr,
                    )
                    if res.status_code != 200:
                        module.fail_json(
                            msg="Failed to delete policy rule {0}. Error: {1}".format(
                                module.params["name"], res.errors[0].message
                            )
                        )
    else:
        changed = True
        if not module.check_mode:
            res = blade.delete_policies(names=[module.params["name"]])
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to delete policy {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def create_snap_policy(module, blade):
    """Create REST 2 snapshot policy"""
    changed = True
    if (
        module.params["keep_for"]
        and not module.params["every"]
        or module.params["every"]
        and not module.params["keep_for"]
    ):
        module.fail_json(msg="`keep_for` and `every` are required.")
    if module.params["timezone"] and not module.params["at"]:
        module.fail_json(msg="`timezone` requires `at` to be provided.")
    if module.params["at"] and not module.params["every"]:
        module.fail_json(msg="`at` requires `every` to be provided.")

    if not module.check_mode:
        if module.params["at"] and module.params["every"]:
            if not module.params["every"] % 86400 == 0:
                module.fail_json(
                    msg="At time can only be set if every value is a multiple of 86400"
                )
            if not module.params["timezone"]:
                module.params["timezone"] = _get_local_tz(module)
                if module.params["timezone"] not in pytz.all_timezones_set:
                    module.fail_json(
                        msg="Timezone {0} is not valid".format(
                            module.params["timezone"]
                        )
                    )
        if not module.params["keep_for"]:
            module.params["keep_for"] = 0
        if not module.params["every"]:
            module.params["every"] = 0
        if module.params["keep_for"] < module.params["every"]:
            module.fail_json(
                msg="Retention period cannot be less than snapshot interval."
            )
        if module.params["at"] and not module.params["timezone"]:
            module.params["timezone"] = _get_local_tz(module)
            if module.params["timezone"] not in set(pytz.all_timezones_set):
                module.fail_json(
                    msg="Timezone {0} is not valid".format(module.params["timezone"])
                )

        if module.params["keep_for"]:
            if not 300 <= module.params["keep_for"] <= 34560000:
                module.fail_json(
                    msg="keep_for parameter is out of range (300 to 34560000)"
                )
            if not 300 <= module.params["every"] <= 34560000:
                module.fail_json(
                    msg="every parameter is out of range (300 to 34560000)"
                )
            if module.params["at"]:
                attr = Policy(
                    enabled=module.params["enabled"],
                    rules=[
                        PolicyRule(
                            keep_for=module.params["keep_for"] * 1000,
                            every=module.params["every"] * 1000,
                            at=_convert_to_millisecs(module.params["at"]),
                            time_zone=module.params["timezone"],
                        )
                    ],
                )
            else:
                attr = Policy(
                    enabled=module.params["enabled"],
                    rules=[
                        PolicyRule(
                            keep_for=module.params["keep_for"] * 1000,
                            every=module.params["every"] * 1000,
                        )
                    ],
                )
        else:
            attr = Policy(enabled=module.params["enabled"])
        res = blade.post_policies(names=[module.params["name"]], policy=attr)
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to create snapshot policy {0}. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def create_policy(module, blade):
    """Create snapshot policy"""
    changed = True
    if not module.check_mode:
        try:
            if module.params["at"] and module.params["every"]:
                if not module.params["every"] % 86400 == 0:
                    module.fail_json(
                        msg="At time can only be set if every value is a multiple of 86400"
                    )
                if not module.params["timezone"]:
                    module.params["timezone"] = _get_local_tz(module)
                    if module.params["timezone"] not in pytz.all_timezones_set:
                        module.fail_json(
                            msg="Timezone {0} is not valid".format(
                                module.params["timezone"]
                            )
                        )
            if not module.params["keep_for"]:
                module.params["keep_for"] = 0
            if not module.params["every"]:
                module.params["every"] = 0
            if module.params["keep_for"] < module.params["every"]:
                module.fail_json(
                    msg="Retention period cannot be less than snapshot interval."
                )
            if module.params["at"] and not module.params["timezone"]:
                module.params["timezone"] = _get_local_tz(module)
                if module.params["timezone"] not in set(pytz.all_timezones_set):
                    module.fail_json(
                        msg="Timezone {0} is not valid".format(
                            module.params["timezone"]
                        )
                    )

            if module.params["keep_for"]:
                if not 300 <= module.params["keep_for"] <= 34560000:
                    module.fail_json(
                        msg="keep_for parameter is out of range (300 to 34560000)"
                    )
                if not 300 <= module.params["every"] <= 34560000:
                    module.fail_json(
                        msg="every parameter is out of range (300 to 34560000)"
                    )
                if module.params["at"]:
                    attr = Policy(
                        enabled=module.params["enabled"],
                        rules=[
                            PolicyRule(
                                keep_for=module.params["keep_for"] * 1000,
                                every=module.params["every"] * 1000,
                                at=_convert_to_millisecs(module.params["at"]),
                                time_zone=module.params["timezone"],
                            )
                        ],
                    )
                else:
                    attr = Policy(
                        enabled=module.params["enabled"],
                        rules=[
                            PolicyRule(
                                keep_for=module.params["keep_for"] * 1000,
                                every=module.params["every"] * 1000,
                            )
                        ],
                    )
            else:
                attr = Policy(enabled=module.params["enabled"])
            blade.policies.create_policies(names=[module.params["name"]], policy=attr)
        except Exception:
            module.fail_json(
                msg="Failed to create policy {0}.".format(module.params["name"])
            )
        if module.params["filesystem"]:
            try:
                blade.file_systems.list_file_systems(names=module.params["filesystem"])
                blade.policies.create_policy_filesystems(
                    policy_names=[module.params["name"]],
                    member_names=module.params["filesystem"],
                )
            except Exception:
                blade.policies.delete_policies(names=[module.params["name"]])
                module.fail_json(
                    msg="Failed to connect filesystems to policy {0}, "
                    "or one of {1} doesn't exist.".format(
                        module.params["name"], module.params["filesystem"]
                    )
                )
        if module.params["replica_link"]:
            for link in module.params["replica_link"]:
                remote_array = (
                    blade.file_system_replica_links.list_file_system_replica_links(
                        local_file_system_names=[link]
                    )
                )
                try:
                    blade.policies.create_policy_file_system_replica_links(
                        policy_names=[module.params["name"]],
                        member_names=[link],
                        remote_names=[remote_array.items[0].remote.name],
                    )
                except Exception:
                    blade.policies.delete_policies(names=[module.params["name"]])
                    module.fail_json(
                        msg="Failed to connect filesystem replicsa link {0} to policy {1}. "
                        "Replica Link {0} does not exist.".format(
                            link, module.params["name"]
                        )
                    )
    module.exit_json(changed=changed)


def update_snap_policy(module, blade):
    """Update REST 2 snapshot policy

    Add new rules to the policy using this function.
    Should it be necessary to modify an existing rule these are the rules:

    Due to the 'best fit' nature of Purity we only add new rulkes in this function.
    If you trying to update an existing rule, then this should be done by deleting
    the current rule and then adding the new rule.

    Purity may recover some snapshots as long as the add happens before the eradication delay
    (typically 24h) causes the snapshots to be eradicated.
    """

    changed = False
    if (
        module.params["keep_for"]
        and not module.params["every"]
        or module.params["every"]
        and not module.params["keep_for"]
    ):
        module.fail_json(msg="`keep_for` and `every` are required.")
    if module.params["timezone"] and not module.params["at"]:
        module.fail_json(msg="`timezone` requires `at` to be provided.")
    if module.params["at"] and not module.params["every"]:
        module.fail_json(msg="`at` requires `every` to be provided.")
    current_rules = list(blade.get_policies(names=[module.params["name"]]).items)[
        0
    ].rules
    create_new = True
    for rule in range(0, len(current_rules)):
        current_rule = {
            "at": current_rules[rule].at,
            "every": current_rules[rule].every,
            "keep_for": current_rules[rule].keep_for,
            "time_zone": current_rules[rule].time_zone,
        }
        if not module.params["at"]:
            new_at = current_rules[rule].at
        else:
            new_at = _convert_to_millisecs(module.params["at"])
        if module.params["keep_for"]:
            new_keep_for = module.params["keep_for"]
        else:
            new_keep_for = int(current_rules[rule].keep_for / 1000)
        if module.params["every"]:
            new_every = module.params["every"]
        else:
            new_every = int(current_rules[rule].every / 1000)
        if not module.params["timezone"]:
            new_tz = current_rules[rule].time_zone
        else:
            new_tz = module.params["timezone"]
        new_rule = {
            "at": new_at,
            "every": new_every * 1000,
            "keep_for": new_keep_for * 1000,
            "time_zone": new_tz,
        }
        if current_rule == new_rule:
            create_new = False

    if create_new:
        changed = True
        if not module.check_mode:
            if module.params["at"] and module.params["every"]:
                if not module.params["every"] % 86400 == 0:
                    module.fail_json(
                        msg="At time can only be set if every value is a multiple of 86400"
                    )
                if not module.params["timezone"]:
                    module.params["timezone"] = _get_local_tz(module)
                    if module.params["timezone"] not in pytz.all_timezones_set:
                        module.fail_json(
                            msg="Timezone {0} is not valid".format(
                                module.params["timezone"]
                            )
                        )
            if not module.params["keep_for"]:
                module.params["keep_for"] = 0
            if not module.params["every"]:
                module.params["every"] = 0
            if module.params["keep_for"] < module.params["every"]:
                module.fail_json(
                    msg="Retention period cannot be less than snapshot interval."
                )
            if module.params["at"] and not module.params["timezone"]:
                module.params["timezone"] = _get_local_tz(module)
                if module.params["timezone"] not in set(pytz.all_timezones_set):
                    module.fail_json(
                        msg="Timezone {0} is not valid".format(
                            module.params["timezone"]
                        )
                    )

            if module.params["keep_for"]:
                if not 300 <= module.params["keep_for"] <= 34560000:
                    module.fail_json(
                        msg="keep_for parameter is out of range (300 to 34560000)"
                    )
                if not 300 <= module.params["every"] <= 34560000:
                    module.fail_json(
                        msg="every parameter is out of range (300 to 34560000)"
                    )
                if module.params["at"]:
                    attr = PolicyPatch(
                        enabled=module.params["enabled"],
                        add_rules=[
                            PolicyRule(
                                keep_for=module.params["keep_for"] * 1000,
                                every=module.params["every"] * 1000,
                                at=_convert_to_millisecs(module.params["at"]),
                                time_zone=module.params["timezone"],
                            )
                        ],
                    )
                else:
                    attr = PolicyPatch(
                        enabled=module.params["enabled"],
                        add_rules=[
                            PolicyRule(
                                keep_for=module.params["keep_for"] * 1000,
                                every=module.params["every"] * 1000,
                            )
                        ],
                    )
            else:
                attr = PolicyPatch(enabled=module.params["enabled"])
            res = blade.patch_policies(
                names=[module.params["name"]],
                policy=attr,
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to update snapshot policy {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def update_policy(module, blade, policy):
    """Update snapshot policy"""
    changed = False
    if not policy.rules:
        current_policy = {
            "time_zone": None,
            "every": 0,
            "keep_for": 0,
            "at": 0,
            "enabled": policy.enabled,
        }
    else:
        if policy.rules[0].keep_for != 0:
            policy.rules[0].keep_for = int(policy.rules[0].keep_for / 1000)
        if policy.rules[0].every != 0:
            policy.rules[0].every = int(policy.rules[0].every / 1000)

        current_policy = {
            "time_zone": policy.rules[0].time_zone,
            "every": policy.rules[0].every,
            "keep_for": policy.rules[0].keep_for,
            "at": policy.rules[0].at,
            "enabled": policy.enabled,
        }
    if not module.params["every"]:
        every = 0
    else:
        every = module.params["every"]
    if not module.params["keep_for"]:
        keep_for = 0
    else:
        keep_for = module.params["keep_for"]
    if module.params["at"]:
        at_time = _convert_to_millisecs(module.params["at"])
    else:
        at_time = None
    if not module.params["timezone"]:
        timezone = _get_local_tz(module)
    else:
        timezone = module.params["timezone"]
    if at_time:
        new_policy = {
            "time_zone": timezone,
            "every": every,
            "keep_for": keep_for,
            "at": at_time,
            "enabled": module.params["enabled"],
        }
    else:
        new_policy = {
            "time_zone": None,
            "every": every,
            "keep_for": keep_for,
            "at": None,
            "enabled": module.params["enabled"],
        }
    if (
        new_policy["time_zone"]
        and new_policy["time_zone"] not in pytz.all_timezones_set
    ):
        module.fail_json(
            msg="Timezone {0} is not valid".format(module.params["timezone"])
        )

    if current_policy != new_policy:
        if not module.params["at"]:
            module.params["at"] = current_policy["at"]
        if not module.params["keep_for"]:
            module.params["keep_for"] = current_policy["keep_for"]
        if not module.params["every"]:
            module.params["every"] = current_policy["every"]
        if module.params["at"] and module.params["every"]:
            if not module.params["every"] % 86400 == 0:
                module.fail_json(
                    msg="At time can only be set if every value is a multiple of 86400"
                )
        if module.params["keep_for"] < module.params["every"]:
            module.fail_json(
                msg="Retention period cannot be less than snapshot interval."
            )
        if module.params["at"] and not module.params["timezone"]:
            module.params["timezone"] = _get_local_tz(module)
            if module.params["timezone"] not in set(pytz.all_timezones_set):
                module.fail_json(
                    msg="Timezone {0} is not valid".format(module.params["timezone"])
                )

        changed = True
        if not module.check_mode:
            try:
                attr = PolicyPatch()
                attr.enabled = module.params["enabled"]
                if at_time:
                    attr.add_rules = [
                        PolicyRule(
                            keep_for=module.params["keep_for"] * 1000,
                            every=module.params["every"] * 1000,
                            at=at_time,
                            time_zone=timezone,
                        )
                    ]
                else:
                    attr.add_rules = [
                        PolicyRule(
                            keep_for=module.params["keep_for"] * 1000,
                            every=module.params["every"] * 1000,
                        )
                    ]
                attr.remove_rules = [
                    PolicyRule(
                        keep_for=current_policy["keep_for"] * 1000,
                        every=current_policy["every"] * 1000,
                        at=current_policy["at"],
                        time_zone=current_policy["time_zone"],
                    )
                ]
                blade.policies.update_policies(
                    names=[module.params["name"]], policy_patch=attr
                )
            except Exception:
                module.fail_json(
                    msg="Failed to update policy {0}.".format(module.params["name"])
                )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            state=dict(
                type="str", default="present", choices=["absent", "present", "copy"]
            ),
            policy_type=dict(
                type="str", default="snapshot", choices=["snapshot", "access", "nfs"]
            ),
            enabled=dict(type="bool", default=True),
            timezone=dict(type="str"),
            name=dict(type="str"),
            at=dict(type="str"),
            every=dict(type="int"),
            keep_for=dict(type="int"),
            filesystem=dict(type="list", elements="str"),
            replica_link=dict(type="list", elements="str"),
            account=dict(type="str"),
            target=dict(type="str"),
            target_rule=dict(type="str"),
            rename=dict(type="str"),
            rule=dict(type="str"),
            user=dict(type="str"),
            effect=dict(type="str", default="allow", choices=["allow"]),
            actions=dict(
                type="list",
                elements="str",
                choices=[
                    "s3:*",
                    "s3:AbortMultipartUpload",
                    "s3:CreateBucket",
                    "s3:DeleteBucket",
                    "s3:DeleteObject",
                    "s3:DeleteObjectVersion",
                    "s3:ExtendSafemodeRetentionPeriod",
                    "s3:GetBucketAcl",
                    "s3:GetBucketLocation",
                    "s3:GetBucketVersioning",
                    "s3:GetLifecycleConfiguration",
                    "s3:GetObject",
                    "s3:GetObjectAcl",
                    "s3:GetObjectVersion",
                    "s3:ListAllMyBuckets",
                    "s3:ListBucket",
                    "s3:ListBucketMultipartUploads",
                    "s3:ListBucketVersions",
                    "s3:ListMultipartUploadParts",
                    "s3:PutBucketVersioning",
                    "s3:PutLifecycleConfiguration",
                    "s3:PutObject",
                ],
            ),
            object_resources=dict(type="list", elements="str"),
            source_ips=dict(type="list", elements="str"),
            s3_prefixes=dict(type="list", elements="str"),
            s3_delimiters=dict(type="list", elements="str"),
            ignore_enforcement=dict(type="bool", default=True),
            force_delete=dict(type="bool", default=False),
            access=dict(
                type="str",
                choices=["root-squash", "all-squash", "no-squash"],
                default="root-squash",
            ),
            anonuid=dict(type="str"),
            anongid=dict(type="str"),
            atime=dict(type="bool", default=True),
            client=dict(type="str", default="*"),
            fileid_32bit=dict(type="bool", default=False),
            permission=dict(type="str", choices=["rw", "ro"], default="ro"),
            secure=dict(type="bool", default=False),
            destroy_snapshots=dict(type="bool", default=False),
            security=dict(
                type="list",
                elements="str",
                choices=["sys", "krb5", "krb5i", "krb5p"],
                default=["sys"],
            ),
            before_rule=dict(type="int"),
        )
    )

    required_together = [["keep_for", "every"]]
    required_if = [
        ["policy_type", "access", ["account", "name"]],
        ["policy_type", "nfs", ["name"]],
    ]

    module = AnsibleModule(
        argument_spec,
        required_together=required_together,
        required_if=required_if,
        supports_check_mode=True,
    )

    if not HAS_PURITYFB:
        module.fail_json(msg="purity-fb sdk is required for this module")
    if not HAS_PYTZ:
        module.fail_json(msg="pytz is required for this module")

    state = module.params["state"]
    blade = get_blade(module)
    versions = blade.api_version.list_versions().versions
    if module.params["policy_type"] == "access":
        if ACCESS_POLICY_API_VERSION not in versions:
            module.fail_json(
                msg=(
                    "Minimum FlashBlade REST version required: {0}".format(
                        ACCESS_POLICY_API_VERSION
                    )
                )
            )
        if not HAS_PYPURECLIENT:
            module.fail_json(msg="py-pure-client sdk is required for this module")
        blade = get_system(module)
        try:
            policy = list(
                blade.get_object_store_access_policies(
                    names=[module.params["account"] + "/" + module.params["name"]]
                ).items
            )[0]
        except AttributeError:
            policy = None
        if module.params["user"]:
            member_name = module.params["account"] + "/" + module.params["user"]
            res = blade.get_object_store_users(filter='name="' + member_name + "'")
            if res.status_code != 200:
                module.fail_json(
                    msg="User {0} does not exist in account {1}".format(
                        module.params["user"], module.params["account"]
                    )
                )
        if policy and state == "present":
            update_os_policy(module, blade)
        elif state == "present" and not policy:
            create_os_policy(module, blade)
        elif state == "absent" and policy:
            delete_os_policy(module, blade)
        elif state == "copy" and module.params["target"] and module.params["rule"]:
            if "/" not in module.params["target"]:
                module.fail_json(
                    msg='Incorrect format for target policy. Must be "<account>/<name>"'
                )
            if (
                blade.get_object_store_access_policies(
                    names=[module.params["target"]]
                ).status_code
                != 200
            ):
                module.fail_json(
                    msg="Target policy {0} does not exist".format(
                        module.params["target"]
                    )
                )
            copy_os_policy_rule(module, blade)
    elif module.params["policy_type"] == "nfs":
        if NFS_POLICY_API_VERSION not in versions:
            module.fail_json(
                msg=(
                    "Minimum FlashBlade REST version required: {0}".format(
                        NFS_POLICY_API_VERSION
                    )
                )
            )
        if not HAS_PYPURECLIENT:
            module.fail_json(msg="py-pure-client sdk is required for this module")
        blade = get_system(module)
        try:
            policy = list(
                blade.get_nfs_export_policies(names=[module.params["name"]]).items
            )[0]
        except AttributeError:
            policy = None
        if module.params["rename"]:
            try:
                new_policy = list(
                    blade.get_nfs_export_policies(names=[module.params["rename"]]).items
                )[0]
            except AttributeError:
                new_policy = None
        if policy and state == "present" and not module.params["rename"]:
            if module.params["before_rule"]:
                res = blade.get_nfs_export_policies_rules(
                    policy_names=[module.params["name"]],
                    names=[
                        module.params["name"] + "." + str(module.params["before_rule"])
                    ],
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Rule index {0} does not exist.".format(
                            module.params["before_rule"]
                        )
                    )
            update_nfs_policy(module, blade)
        elif (
            state == "present" and module.params["rename"] and policy and not new_policy
        ):
            rename_nfs_policy(module, blade)
        elif state == "present" and not policy and not module.params["rename"]:
            create_nfs_policy(module, blade)
        elif state == "absent" and policy:
            delete_nfs_policy(module, blade)
    elif SNAPSHOT_POLICY_API_VERSION in versions:
        if not HAS_PYPURECLIENT:
            module.fail_json(msg="py-pure-client sdk is required for this module")
        blade = get_system(module)
        try:
            policy = list(blade.get_policies(names=[module.params["name"]]).items)[0]
        except AttributeError:
            policy = None
        if not policy and state == "present":
            create_snap_policy(module, blade)
        elif policy and state == "present":
            update_snap_policy(module, blade)
        elif policy and state == "absent":
            delete_snap_policy(module, blade)
    else:
        if MIN_REQUIRED_API_VERSION not in versions:
            module.fail_json(
                msg="Minimum FlashBlade REST version required: {0}".format(
                    MIN_REQUIRED_API_VERSION
                )
            )
        try:
            policy = blade.policies.list_policies(names=[module.params["name"]]).items[
                0
            ]
        except Exception:
            policy = None

        if policy and state == "present":
            update_policy(module, blade, policy)
        elif state == "present" and not policy:
            create_policy(module, blade)
        elif state == "absent" and policy:
            delete_policy(module, blade)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

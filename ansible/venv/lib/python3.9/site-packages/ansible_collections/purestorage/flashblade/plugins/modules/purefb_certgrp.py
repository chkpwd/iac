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
module: purefb_certgrp
version_added: '1.4.0'
short_description: Manage FlashBlade Certifcate Groups
description:
- Manage certifcate groups for FlashBlades
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Create or delete certifcate group
    default: present
    type: str
    choices: [ absent, present ]
  name:
    description:
    - Name of the certificate group
    type: str
  certificates:
    description:
    - List of certifcates to add to a policy on creation
    type: list
    elements: str
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Create a certifcate group
  purestorage.flashblade.purefb_certgrp:
    name: test_grp
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Create a cerifcate group and add existing certificates
  purestorage.flashblade.purefb_certgrp:
    name: test_grp
    certifcates:
    - cert1
    - cert2
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Delete a certifcate from a group
  purestorage.flashblade.purefb_certgrp:
    name: test_grp
    certificates:
    - cert2
    state: absent
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Delete a certifcate group
  purestorage.flashblade.purefb_certgrp:
    name: test_grp
    state: absent
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_blade,
    purefb_argument_spec,
)


MIN_REQUIRED_API_VERSION = "1.9"


def delete_certgrp(module, blade):
    """Delete certifcate group"""
    changed = True
    if not module.check_mode:
        try:
            blade.certificate_groups.delete_certificate_groups(
                names=[module.params["name"]]
            )
        except Exception:
            module.fail_json(
                msg="Failed to delete certifcate group {0}.".format(
                    module.params["name"]
                )
            )
    module.exit_json(changed=changed)


def create_certgrp(module, blade):
    """Create certifcate group"""
    changed = True
    if not module.check_mode:
        try:
            blade.certificate_groups.create_certificate_groups(
                names=[module.params["name"]]
            )
        except Exception:
            module.fail_json(
                msg="Failed to create certificate group {0}.".format(
                    module.params["name"]
                )
            )
        if module.params["certificates"]:
            try:
                blade.certificate_groups.add_certificate_group_certificates(
                    certificate_names=module.params["certificates"],
                    certificate_group_names=[module.params["name"]],
                )
            except Exception:
                blade.certificate_groups.delete_certificate_groups(
                    names=[module.params["name"]]
                )
                module.fail_json(
                    msg="Failed to add certifcates {0}. "
                    "Please check they all exist".format(module.params["certificates"])
                )
    module.exit_json(changed=changed)


def update_certgrp(module, blade):
    """Update certificate group"""
    changed = False
    try:
        certs = blade.certificate_groups.list_certificate_group_certificates(
            certificate_group_names=[module.params["name"]]
        )
    except Exception:
        module.fail_json(
            msg="Failed to get certifates list for group {0}.".format(
                module.params["name"]
            )
        )
    if not certs:
        if module.params["state"] == "present":
            changed = True
            if not module.check_mode:
                try:
                    blade.certificate_groups.add_certificate_group_certificates(
                        certificate_names=module.params["certificates"],
                        certificate_group_names=[module.params["name"]],
                    )
                except Exception:
                    module.fail_json(
                        msg="Failed to add certifcates {0}. "
                        "Please check they all exist".format(
                            module.params["certificates"]
                        )
                    )
    else:
        current = []
        for cert in range(0, len(certs.items)):
            current.append(certs.items[cert].member.name)
        for new_cert in range(0, len(module.params["certificates"])):
            certificate = module.params["certificates"][new_cert]
            if certificate in current:
                if module.params["state"] == "absent":
                    changed = True
                    if not module.check_mode:
                        try:
                            blade.certificate_groups.remove_certificate_group_certificates(
                                certificate_names=[certificate],
                                certificate_group_names=[module.params["name"]],
                            )
                        except Exception:
                            module.fail_json(
                                msg="Failed to delete certifcate {0} from group {1}.".format(
                                    certificate, module.params["name"]
                                )
                            )
            else:
                if module.params["state"] == "present":
                    changed = True
                    if not module.check_mode:
                        try:
                            blade.certificate_groups.add_certificate_group_certificates(
                                certificate_names=[certificate],
                                certificate_group_names=[module.params["name"]],
                            )
                        except Exception:
                            module.fail_json(
                                msg="Failed to add certifcate {0} to group {1}".format(
                                    certificate, module.params["name"]
                                )
                            )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="present", choices=["absent", "present"]),
            name=dict(type="str"),
            certificates=dict(type="list", elements="str"),
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

    try:
        certgrp = blade.certificate_groups.list_certificate_groups(
            names=[module.params["name"]]
        ).items[0]
    except Exception:
        certgrp = None

    if certgrp and state == "present" and module.params["certificates"]:
        update_certgrp(module, blade)
    elif state == "present" and not certgrp:
        create_certgrp(module, blade)
    elif state == "absent" and certgrp:
        if module.params["certificates"]:
            update_certgrp(module, blade)
        else:
            delete_certgrp(module, blade)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

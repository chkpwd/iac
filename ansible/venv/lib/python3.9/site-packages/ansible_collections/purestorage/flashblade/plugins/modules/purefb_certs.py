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
module: purefb_certs
version_added: '1.4.0'
short_description: Manage FlashBlade SSL Certificates
description:
- Manage SSL certificates for FlashBlades
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Create or delete certificate
    default: present
    type: str
    choices: [ absent, present ]
  name:
    description:
    - Name of the certificate
    type: str
  contents:
    description:
    - SSL certificate text
    type: str
  private_key:
    description:
    - SSL certificate private key test
    type: str
  passphrase:
    description:
    - Passphrase for the private_key
    type: str
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Create a SSL certificate
  purestorage.flashblade.purefb_certs:
    name: test_cert
    contents: "{{lookup('file', 'certificate_file_name') }}"
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Delete a SSL certificate
  purestorage.flashblade.purefb_certs:
    name: test_cert
    state: absent
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Update SSL certificate
  purestorage.flashblade.purefb_certs:
    name: global
    contents: "{{ lookup('file', 'certificate_file_name') }}"
    private_key: "{{ lookup('file', 'certificate_key_file_name') }}"
    passphrase: 'mypassword'
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
"""

RETURN = r"""
"""

HAS_PURITYFB = True
try:
    from purity_fb import Certificate, CertificatePost
except ImportError:
    HAS_PURITYFB = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_blade,
    purefb_argument_spec,
)


MIN_REQUIRED_API_VERSION = "1.9"


def delete_cert(module, blade):
    """Delete certificate"""
    changed = True
    if not module.check_mode:
        try:
            blade.certificates.delete_certificates(names=[module.params["name"]])
        except Exception:
            module.fail_json(
                msg="Failed to delete certificate {0}.".format(module.params["name"])
            )
    module.exit_json(changed=changed)


def create_cert(module, blade):
    """Create certificate"""
    changed = True
    if not module.check_mode:
        try:
            body = CertificatePost(
                certificate=module.params["contents"], certificate_type="external"
            )
            blade.certificates.create_certificates(
                names=[module.params["name"]], certificate=body
            )
        except Exception:
            module.fail_json(
                msg="Failed to create certificate {0}.".format(module.params["name"])
            )
    module.exit_json(changed=changed)


def update_cert(module, blade, cert):
    """Update certificate"""
    changed = False
    if cert.certificate_type == "external":
        module.fail_json(msg="External certificates cannot be modified")

    if not module.params["private_key"]:
        module.fail_json(msg="private_key must be specified for the global certificate")

    if cert.certificate.strip() != module.params["contents"].strip():
        changed = True
        if not module.check_mode:
            try:
                body = Certificate(
                    certificate=module.params["contents"],
                    private_key=module.params["private_key"],
                )
                if module.params["passphrase"]:
                    Certificate.passphrase = module.params["passphrase"]
                blade.certificates.update_certificates(
                    names=[module.params["name"]], certificate=body
                )
            except Exception:
                module.fail_json(
                    msg="Failed to create certificate {0}.".format(
                        module.params["name"]
                    )
                )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="present", choices=["absent", "present"]),
            name=dict(type="str"),
            contents=dict(type="str", no_log=True),
            private_key=dict(type="str", no_log=True),
            passphrase=dict(type="str", no_log=True),
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
        cert = blade.certificates.list_certificates(names=[module.params["name"]])
    except Exception:
        cert = None

    if not cert and state == "present":
        create_cert(module, blade)
    elif state == "present":
        update_cert(module, blade, cert.items[0])
    elif state == "absent" and cert:
        delete_cert(module, blade)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

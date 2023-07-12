#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2019 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: ssh_key
short_description: Add, remove or update SSH key
version_added: 1.2.0
author:
  - Felix Fontein (@felixfontein)
description:
  - Add, remove or update an SSH key stored in Hetzner's Robot.
seealso:
  - module: community.hrobot.ssh_key_info
    description: Query information on SSH keys
extends_documentation_fragment:
  - community.hrobot.robot
  - community.hrobot.attributes
  - community.hrobot.attributes.actiongroup_robot

attributes:
  action_group:
    version_added: 1.6.0
  check_mode:
    support: full
  diff_mode:
    support: none

options:
    state:
        description:
          - Whether to make sure a public SSH key is present or absent.
          - C(present) makes sure that the SSH key is available, and
            potentially updates names for existing SHS public keys.
          - C(absent) makes sure that the SSH key is not available.
            The fingerprint or public key data is used for matching the
            key.
        required: true
        type: str
        choices:
          - present
          - absent
    name:
        description:
          - The public key's name.
          - Required if I(state=present), and ignored if I(state=absent).
        type: str
    fingerprint:
        description:
          - The MD5 fingerprint of the public SSH key to remove.
          - One of I(public_key) and I(fingerprint) are required if I(state=absent).
        type: str
    public_key:
        description:
          - The public key data in OpenSSH format.
          - "Example: C(ssh-rsa AAAAB3NzaC1yc+...)"
          - One of I(public_key) and I(fingerprint) are required if I(state=absent).
          - Required if I(state=present).
        type: str
'''

EXAMPLES = r'''
- name: Add an SSH key
  community.hrobot.ssh_key:
    hetzner_user: foo
    hetzner_password: bar
    state: present
    name: newKey
    public_key: ssh-rsa AAAAB3NzaC1yc+...

- name: Remove a SSH key by fingerprint
  community.hrobot.ssh_key:
    hetzner_user: foo
    hetzner_password: bar
    state: absent
    fingerprint: cb:8b:ef:a7:fe:04:87:3f:e5:55:cd:12:e3:e8:9f:99
'''

RETURN = r'''
fingerprint:
    description:
      - The MD5 fingerprint of the key.
      - This is the value used to reference the SSH public key, for example in the M(community.hrobot.boot) module.
    returned: success
    type: str
    sample: cb:8b:ef:a7:fe:04:87:3f:e5:55:cd:12:e3:e8:9f:99
'''

import base64
import binascii
import re

from ansible.module_utils.basic import AnsibleModule, AVAILABLE_HASH_ALGORITHMS
from ansible.module_utils.common.text.converters import to_native
from ansible.module_utils.six.moves.urllib.parse import urlencode

from ansible_collections.community.hrobot.plugins.module_utils.robot import (
    BASE_URL,
    ROBOT_DEFAULT_ARGUMENT_SPEC,
    fetch_url_json,
)


class FingerprintError(Exception):
    pass


SPACE_RE = re.compile(' +')
FINGERPRINT_PART = re.compile('^[0-9a-f]{2}$')


def normalize_fingerprint(fingerprint, size=16):
    if ':' in fingerprint:
        fingerprint = fingerprint.split(':')
    else:
        fingerprint = [fingerprint[i:i + 2] for i in range(0, len(fingerprint), 2)]
    if len(fingerprint) != size:
        raise FingerprintError(
            'Fingerprint must consist of {0} 8-bit hex numbers: got {1} 8-bit hex numbers instead'.format(size, len(fingerprint)))
    for i, part in enumerate(fingerprint):
        new_part = part.lower()
        if len(new_part) < 2:
            new_part = '0{0}'.format(new_part)
        if not FINGERPRINT_PART.match(new_part):
            raise FingerprintError(
                'Fingerprint must consist of {0} 8-bit hex numbers: number {1} is invalid: "{2}"'.format(size, i + 1, part))
        fingerprint[i] = new_part
    return ':'.join(fingerprint)


def extract_fingerprint(public_key, alg='md5', size=16):
    try:
        public_key = SPACE_RE.split(public_key.strip())[1]
    except IndexError:
        raise FingerprintError(
            'Error while extracting fingerprint from public key data: cannot split public key into at least two parts')
    try:
        public_key = base64.b64decode(public_key)
    except (binascii.Error, TypeError) as exc:
        raise FingerprintError(
            'Error while extracting fingerprint from public key data: {0}'.format(exc))
    try:
        algorithm = AVAILABLE_HASH_ALGORITHMS[alg]
    except KeyError:
        raise FingerprintError(
            'Hash algorithm {0} is not available. Possibly running in FIPS mode.'.format(alg.upper()))
    digest = algorithm()
    digest.update(public_key)
    return normalize_fingerprint(digest.hexdigest(), size=size)


def main():
    argument_spec = dict(
        state=dict(type='str', required=True, choices=['present', 'absent']),
        name=dict(type='str'),
        fingerprint=dict(type='str'),
        public_key=dict(type='str'),
    )
    argument_spec.update(ROBOT_DEFAULT_ARGUMENT_SPEC)
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[
            ('fingerprint', 'public_key'),
        ],
        required_if=[
            ('state', 'present', ['name', 'public_key']),
            ('state', 'absent', ['fingerprint', 'public_key'], True),
        ],
    )

    state = module.params['state']
    name = module.params['name']
    fingerprint = module.params['fingerprint']
    public_key = module.params['public_key']

    try:
        if fingerprint is not None:
            fingerprint = normalize_fingerprint(fingerprint)
        else:
            fingerprint = extract_fingerprint(public_key)
    except FingerprintError as exc:
        module.fail_json(msg=to_native(exc))

    url = "{0}/key/{1}".format(BASE_URL, fingerprint)

    # Remove key
    if state == 'absent':
        if module.check_mode:
            dummy, error = fetch_url_json(module, url, accept_errors=['NOT_FOUND'])
        else:
            dummy, error = fetch_url_json(module, url, accept_errors=['NOT_FOUND'], method='DELETE', allow_empty_result=True)
        if error == 'NOT_FOUND':
            changed = False
        elif error is not None:
            raise AssertionError('Unexpected error {0}'.format(error))  # pragma: no cover
        else:
            changed = True
        module.exit_json(changed=changed, fingerprint=fingerprint)

    # Make sure key is present
    result, error = fetch_url_json(module, url, accept_errors=['NOT_FOUND'])
    if error == 'NOT_FOUND':
        changed = True
        exists = False
    elif error is not None:
        raise AssertionError('Unexpected error {0}'.format(error))  # pragma: no cover
    else:
        exists = True
        changed = False
        # The only thing we can update is the name
        if result['key'].get('name') != name:
            changed = True

    if changed and not module.check_mode:
        data = {
            'name': name,
        }
        if not exists:
            # Create key
            data['data'] = ' '.join(SPACE_RE.split(public_key.strip())[:2])
            url = "{0}/key".format(BASE_URL)
        # Update or create key
        headers = {"Content-type": "application/x-www-form-urlencoded"}
        result, dummy = fetch_url_json(
            module,
            url,
            data=urlencode(data),
            headers=headers,
            method='POST',
        )

    module.exit_json(changed=changed, fingerprint=fingerprint)


if __name__ == '__main__':  # pragma: no cover
    main()  # pragma: no cover

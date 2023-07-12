# -*- coding: utf-8 -*-

# Copyright (c) 2022, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
name: _latest_version
short_description: "[INTERNAL] Get latest version from a list of versions"
version_added: 1.4.0
author:
  - Felix Fontein (@felixfontein)
description:
  - B(This is an internal tool and must only be used from roles in this collection!)
    If you use it from outside this collection, be warned that its behavior can change
    and it can be removed at any time, even in bugfix releases!
  - Given a list of version numbers, returns the largest of them.
options:
  _input:
    description:
      - A list of strings. Every string must be a version number.
    type: list
    elements: string
    required: true
'''

EXAMPLES = '''
- name: Print latest version
  ansible.builtin.debug:
    msg: "{{ versions | community.sops._latest_version }}"
  vars:
    versions:
      - 1.0.0
      - 1.0.0rc1
      - 1.1.0
'''

RETURN = '''
_value:
    description:
      - The latest version from the input.
    type: string
'''

from ansible.module_utils.six import raise_from

try:
    from ansible.module_utils.compat.version import LooseVersion
except ImportError:
    try:
        from distutils.version import LooseVersion
    except ImportError as exc:
        msg = (
            'To use this plugin or module with ansible-core 2.11, ansible-base 2.10,'
            ' or Ansible 2.9, you need to use Python < 3.12 with distutils.version present'
        )
        raise_from(ImportError(msg), exc)


def pick_latest_version(version_list):
    '''Pick latest version from a list of versions.'''
    if not version_list:
        return ''
    return sorted(version_list, key=LooseVersion, reverse=True)[0]


class FilterModule(object):
    '''Helper filters.'''
    def filters(self):
        return {
            '_latest_version': pick_latest_version,
        }

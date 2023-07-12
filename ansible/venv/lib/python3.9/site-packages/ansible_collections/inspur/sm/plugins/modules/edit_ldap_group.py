#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright (C) 2020 Inspur Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: edit_ldap_group
version_added: "0.1.0"
author:
    - WangBaoshan (@ISIB-group)
short_description: Set ldap group information.
description:
   - Set ldap group information on Inspur server.
deprecated:
   removed_in: 3.0.0
   why: Merge functions into the M(inspur.sm.ldap_group) module.
   alternative: Use M(inspur.sm.ldap_group) instead.
   removed_from_collection: inspur.sm
options:
    id:
        description:
            - Group id.
        choices: ['1', '2', '3', '4', '5']
        type: str
        required: true
    name:
        description:
            - Group name.
        type: str
    base:
        description:
            - Search Base
            - Search base is a string of 4 to 64 alpha-numeric characters;
            - It must start with an alphabetical character;
            - Special Symbols like dot(.), comma(,), hyphen(-), underscore(_), equal-to(=) are allowed.
        type: str
    pri:
        description:
            - Group privilege.
        choices: ['administrator', 'user', 'operator', 'oem', 'none']
        type: str
    kvm:
        description:
            - Kvm privilege.
        choices: ['enable', 'disable']
        type: str
    vm:
        description:
            - Vmedia privilege.
        choices: ['enable', 'disable']
        type: str
extends_documentation_fragment:
    - inspur.sm.ism
'''

EXAMPLES = '''
- name: Ldap group test
  hosts: ism
  connection: local
  gather_facts: no
  vars:
    ism:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Edit ldap group information"
    inspur.sm.edit_ldap_group:
      id: "1"
      name: "wbs"
      base: "cn=manager"
      pri: "administrator"
      kvm: "enable"
      vm: "disable"
      provider: "{{ ism }}"
'''

RETURN = '''
message:
    description: Messages returned after module execution.
    returned: always
    type: str
state:
    description: Status after module execution.
    returned: always
    type: str
changed:
    description: Check to see if a change was made on the device.
    returned: always
    type: bool
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.inspur.sm.plugins.module_utils.ism import (ism_argument_spec, get_connection)


class LDAP(object):
    def __init__(self, argument_spec):
        self.spec = argument_spec
        self.module = None
        self.init_module()
        self.results = dict()

    def init_module(self):
        """Init module object"""

        self.module = AnsibleModule(
            argument_spec=self.spec, supports_check_mode=False)

    def run_command(self):
        self.module.params['subcommand'] = 'setldapgroup'
        self.results = get_connection(self.module)
        if self.results['State'] == 'Success':
            self.results['changed'] = True

    def show_result(self):
        """Show result"""
        self.module.exit_json(**self.results)

    def work(self):
        """Worker"""
        self.run_command()
        self.show_result()


def main():
    argument_spec = dict(
        id=dict(type='str', required=True, choices=['1', '2', '3', '4', '5']),
        name=dict(type='str', required=False),
        base=dict(type='str', required=False),
        pri=dict(type='str', required=False, choices=['administrator', 'user', 'operator', 'oem', 'none']),
        kvm=dict(type='str', required=False, choices=['enable', 'disable']),
        vm=dict(type='str', required=False, choices=['enable', 'disable']),
    )
    argument_spec.update(ism_argument_spec)
    ldap_obj = LDAP(argument_spec)
    ldap_obj.work()


if __name__ == '__main__':
    main()

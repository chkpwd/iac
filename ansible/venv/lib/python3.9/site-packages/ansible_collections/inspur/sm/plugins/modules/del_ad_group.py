#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright (C) 2020 Inspur Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: del_ad_group
version_added: "0.1.0"
author:
    - WangBaoshan (@ISIB-group)
short_description: Delete active directory group information.
description:
   - Delete active directory group information on Inspur server.
deprecated:
   removed_in: 3.0.0
   why: Merge functions into the M(inspur.sm.ad_group) module.
   alternative: Use M(inspur.sm.ad_group) instead.
   removed_from_collection: inspur.sm
options:
    name:
        description:
            - Group name.
        type: str
        required: true
extends_documentation_fragment:
    - inspur.sm.ism
'''

EXAMPLES = '''
- name: Ad group test
  hosts: ism
  connection: local
  gather_facts: no
  vars:
    ism:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Delete active directory group information"
    inspur.sm.del_ad_group:
      name: "inspur"
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


class AD(object):
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
        self.module.params['subcommand'] = 'deladgroup'
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
        name=dict(type='str', required=True),
    )
    argument_spec.update(ism_argument_spec)
    ad_obj = AD(argument_spec)
    ad_obj.work()


if __name__ == '__main__':
    main()

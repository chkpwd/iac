#!/usr/bin/python

# (c) 2023, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = '''
module: na_ontap_ems_filter
short_description: NetApp ONTAP EMS Filter
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: 22.4.0
author: NetApp Ansible Team (@carchi8py) <ng-ansibleteam@netapp.com>
description:
  - Create, delete, or modify EMS filters on NetApp ONTAP. This module only supports REST.
notes:
  - This module only supports REST.

options:
  state:
    description:
      - Whether the specified user should exist or not.
    choices: ['present', 'absent']
    type: str
    default: 'present'

  name:
    description:
      - Name of the EMS Filter
    required: True
    type: str

  rules:
    description: List of EMS filter rules
    type: list
    elements: dict
    suboptions:
      index:
        description: Index of rule
        type: int
        required: True
      type:
        description: The type of rule
        type: str
        choices: ['include', 'exclude']
        required: True
      message_criteria:
        description: Message criteria for EMS filter, required one of severities, name_pattern when creating ems filter.
        type: dict
        suboptions:
          severities:
            description: comma separated string of severities this rule applies to
            type: str
          name_pattern:
            description:  Name pattern to apply rule to
            type: str
'''

EXAMPLES = """
    - name: Create EMS filter
      netapp.ontap.na_ontap_ems_filter:
        state: present
        name: carchi_ems
        rules:
          - index: 1
            type: include
            message_criteria:
              severities: "error"
              name_pattern: "callhome.*"
          - index: 2
            type: include
            message_criteria:
              severities: "EMERGENCY"

    - name: Modify EMS filter add rule
      netapp.ontap.na_ontap_ems_filter:
        state: present
        name: carchi_ems
        rules:
          - index: 1
            type: include
            message_criteria:
              severities: "error"
              name_pattern: "callhome.*"
          - index: 2
            type: include
            message_criteria:
              severities: "EMERGENCY"
          - index: 3
            type: include
            message_criteria:
              severities: "ALERT"

    - name: Delete EMS Filter
      netapp.ontap.na_ontap_ems_filter:
        state: absent
        name: carchi_ems
"""

RETURN = """
"""

import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppOntapEMSFilters:

    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            name=dict(required=True, type='str'),
            rules=dict(type='list', elements='dict', options=dict(
                index=dict(required=True, type="int"),
                type=dict(required=True, type="str", choices=['include', 'exclude']),
                message_criteria=dict(type="dict", options=dict(
                    severities=dict(required=False, type="str"),
                    name_pattern=dict(required=False, type="str")
                ))
            ))
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )
        self.na_helper = NetAppModule(self.module)
        self.parameters = self.na_helper.check_and_set_parameters(self.module)
        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()
        if not self.use_rest:
            self.module.fail_json(msg="This module require REST with ONTAP 9.6 or higher")

    def get_ems_filter(self):
        api = 'support/ems/filters'
        params = {'name': self.parameters['name'],
                  'fields': "rules"}
        record, error = rest_generic.get_one_record(self.rest_api, api, params)
        if error:
            self.module.fail_json(msg="Error fetching ems filter %s: %s" % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())
        return record

    def create_ems_filter(self):
        api = 'support/ems/filters'
        body = {'name': self.parameters['name']}
        if self.parameters.get('rules'):
            body['rules'] = self.na_helper.filter_out_none_entries(self.parameters['rules'])
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error:
            self.module.fail_json(msg="Error creating EMS filter %s: %s" % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def delete_ems_filter(self):
        api = 'support/ems/filters'
        dummy, error = rest_generic.delete_async(self.rest_api, api, self.parameters['name'])
        if error:
            self.module.fail_json(msg='Error deleting EMS filter %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def modify_ems_filter(self):
        # only variable other than name is rules, so if we hit this we know rules has been changed
        api = 'support/ems/filters'
        body = {'rules': self.na_helper.filter_out_none_entries(self.parameters['rules'])}
        dummy, error = rest_generic.patch_async(self.rest_api, api, self.parameters['name'], body)
        if error:
            self.module.fail_json(msg='Error modifying EMS filter %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def find_modify(self, current):
        # The normal modify will not work for 2 reasons
        # First ems filter will add a new rule at the end that excludes everything that there isn't a rule for
        # Second Options that are not given are returned as '*' in rest
        if not current:
            return False
        # Modify Current to remove auto added rule, from testing it always appears to be the last element
        if current.get('rules'):
            current['rules'].pop()
        # Next check if both have no rules
        if current.get('rules') is None and self.parameters.get('rules') is None:
            return False
        # Next let check if rules is the same size if not we need to modify
        if len(current.get('rules')) != len(self.parameters.get('rules')):
            return True
        # Next let put the current rules in a dictionary by rule number
        current_rules = self.dic_of_rules(current)
        # Now we need to compare each field to see if there is a match
        modify = False
        for rule in self.parameters['rules']:
            # allow modify if a desired rule index may not exist in current rules.
            # when testing found only index 1, 2 are allowed, if try to set index other than this, let REST throw error.
            if current_rules.get(rule['index']) is None:
                modify = True
                break
            # Check if types are the same
            if rule['type'].lower() != current_rules[rule['index']]['type'].lower():
                modify = True
                break
            if rule.get('message_criteria'):
                if rule['message_criteria'].get('severities') and rule['message_criteria']['severities'].lower() != \
                        current_rules[rule['index']]['message_criteria']['severities'].lower():
                    modify = True
                    break
                if rule['message_criteria'].get('name_pattern') and rule['message_criteria']['name_pattern'] != \
                        current_rules[rule['index']]['message_criteria']['name_pattern']:
                    modify = True
                    break
        return modify

    def dic_of_rules(self, current):
        rules = {}
        for rule in current['rules']:
            rules[rule['index']] = rule
        return rules

    def apply(self):
        current = self.get_ems_filter()
        cd_action, modify = None, False
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action is None:
            modify = self.find_modify(current)
            if modify:
                self.na_helper.changed = True
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_ems_filter()
            if cd_action == 'delete':
                self.delete_ems_filter()
            if modify:
                self.modify_ems_filter()
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    '''Apply volume operations from playbook'''
    obj = NetAppOntapEMSFilters()
    obj.apply()


if __name__ == '__main__':
    main()

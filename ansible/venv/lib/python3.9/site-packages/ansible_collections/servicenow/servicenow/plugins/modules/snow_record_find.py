#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Ansible Project
# Copyright: (c) 2017, Tim Rightnour <thegarbledone@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: snow_record_find
short_description: Search for multiple records from ServiceNow
description:
    - Gets multiple records from a specified table from ServiceNow based on a query dictionary.
options:
    table:
      description:
      - Table to query for records.
      type: str
      required: false
      default: incident
    query:
      description:
      - Dict to query for records.
      type: dict
      required: true
    max_records:
      description:
      - Maximum number of records to return.
      type: int
      required: false
      default: 20
    display_value:
      description:
      - sysparm_display_value
      type: bool
      required: false
      default: false
    exclude_reference_link:
      description:
      - sysparm_exclude_reference_link
      type: bool
      required: false
      default: false
    suppress_pagination_header:
      description:
      - sysparm_suppress_pagination_header
      type: bool
      required: false
      default: false
    order_by:
      description:
      - Field to sort the results on.
      - Can prefix with "-" or "+" to change descending or ascending sort order.
      type: str
      default: "-created_on"
      required: false
    return_fields:
      description:
      - Fields of the record to return in the json.
      - By default, all fields will be returned.
      type: list
      required: false
      elements: str
requirements:
    - python pysnow (pysnow)
    - python requests (requests)
author:
    - Tim Rightnour (@garbled1)
extends_documentation_fragment:
- servicenow.servicenow.service_now.documentation

'''

EXAMPLES = r'''
- name: Search for incident assigned to group, return specific fields
  servicenow.servicenow.snow_record_find:
    username: ansible_test
    password: my_password
    instance: dev99999
    table: incident
    query:
      assignment_group: d625dccec0a8016700a222a0f7900d06
    return_fields:
      - number
      - opened_at

- name: Search for incident assigned to group, explicitly using basic authentication, return specific fields, and suppress exception if not found
  servicenow.servicenow.snow_record_find:
    auth: basic
    username: ansible_test
    password: my_password
    instance: dev99999
    raise_on_empty: False
    table: incident
    query:
      assignment_group: d625dccec0a8016700a222a0f7900d06
    return_fields:
      - number
      - opened_at

- name: Search for incident using host instead of instance
  servicenow.servicenow.snow_record_find:
    username: ansible_test
    password: my_password
    host: dev99999.mycustom.domain.com
    table: incident
    query:
      assignment_group: d625dccec0a8016700a222a0f7900d06
    return_fields:
      - number
      - opened_at

- name: Using OAuth, search for incident assigned to group, return specific fields
  servicenow.servicenow.snow_record_find:
    auth: oauth
    username: ansible_test
    password: my_password
    client_id: "1234567890abcdef1234567890abcdef"
    client_secret: "Password1!"
    instance: dev99999
    table: incident
    query:
      assignment_group: d625dccec0a8016700a222a0f7900d06
    return_fields:
      - number
      - opened_at

- name: Using a bearer token, search for incident assigned to group, return specific fields
  servicenow.servicenow.snow_record_find:
    auth: token
    username: ansible_test
    password: my_password
    token: "y0urHorrend0u51yL0ngT0kenG0esH3r3..."
    instance: dev99999
    table: incident
    query:
      assignment_group: d625dccec0a8016700a222a0f7900d06
    return_fields:
      - number
      - opened_at

- name: Using OpenID, search for incident assigned to group, return specific fields
  servicenow.servicenow.snow_record_find:
    auth: openid
    username: ansible_test
    password: my_password
    client_id: "1234567890abcdef1234567890abcdef"
    client_secret: "Password1!"
    openid_issuer: "https://yourorg.oktapreview.com/oauth2/TH151s50M3L0ngStr1NG"
    openid_scope: "openid email"
    instance: dev99999
    table: incident
    query:
      assignment_group: d625dccec0a8016700a222a0f7900d06
    return_fields:
      - number
      - opened_at
  register: response

- name: Using previous OpenID response, search for incident assigned to group, return specific fields
  servicenow.servicenow.snow_record_find:
    auth: openid
    username: ansible_test
    password: my_password
    client_id: "1234567890abcdef1234567890abcdef"
    client_secret: "Password1!"
    openid: "{{ response['openid'] }}"
    instance: dev99999
    table: incident
    query:
      assignment_group: d625dccec0a8016700a222a0f7900d06
    return_fields:
      - number
      - opened_at

- name: Find open standard changes with my template
  servicenow.servicenow.snow_record_find:
    username: ansible_test
    password: my_password
    instance: dev99999
    table: change_request
    query:
      AND:
        equals:
          active: "True"
          type: "standard"
          u_change_stage: "80"
        contains:
          u_template: "MY-Template"
    return_fields:
      - sys_id
      - number
      - sys_created_on
      - sys_updated_on
      - u_template
      - active
      - type
      - u_change_stage
      - sys_created_by
      - description
      - short_description
'''

RETURN = r'''
record:
    description: The full contents of the matching ServiceNow records as a list of records.
    type: dict
    returned: always
'''

from ansible_collections.servicenow.servicenow.plugins.module_utils.service_now import ServiceNowModule
from ansible.module_utils._text import to_native

try:
    # This is being managed by ServiceNowModule
    import pysnow
    import re
    import requests
except ImportError:
    pass


class SnowRecordFind(object):
    '''
    This is a BuildQuery manipulation class that constructs
    a pysnow.QueryBuilder object based on data input.
    '''

    def __init__(self, module):
        self.module = module

        # Define query parameters
        self.data = module.params['query']
        self.max_records = self.module.params['max_records']
        self.order_by = self.module.params['order_by']
        self.return_fields = self.module.params['return_fields']

        # Define sort criteria
        self.reverse = False
        if self.order_by is not None:
            if self.order_by[0] == '-':
                self.reverse = True
            if self.order_by[0] in ['-', '+']:
                self.order_by = self.order_by[1:]

        # Define table parameters
        self.table = module.connection.resource(
            api_path='/table/' + self.module.params['table'])
        self.table.parameters.display_value = self.module.params['display_value']
        self.table.parameters.exclude_reference_link = self.module.params[
            'exclude_reference_link']
        self.table.parameters.suppress_pagination_header = self.module.params[
            'suppress_pagination_header']

        # Define query expression operators
        self.logic_operators = ["AND", "OR", "NQ"]
        self.condition_operator = {
            'equals': self._condition_closure,
            'not_equals': self._condition_closure,
            'contains': self._condition_closure,
            'not_contains': self._condition_closure,
            'starts_with': self._condition_closure,
            'ends_with': self._condition_closure,
            'greater_than': self._condition_closure,
            'less_than': self._condition_closure,
        }
        self.accepted_cond_ops = self.condition_operator.keys()
        self.append_operator = False
        self.simple_query = True

        # Build the query
        self.query = pysnow.QueryBuilder()
        self._iterate_operators(self.data)

    def _condition_closure(self, cond, query_field, query_value):
        self.query.field(query_field)
        getattr(self.query, cond)(query_value)

    def _iterate_fields(self, data, logic_op, cond_op):
        if isinstance(data, dict):
            for query_field, query_value in data.items():
                if self.append_operator:
                    getattr(self.query, logic_op)()
                self.condition_operator[cond_op](
                    cond_op, query_field, query_value)
                self.append_operator = True
        else:
            self.module.fail(msg='Query is not in a supported format')

    def _iterate_conditions(self, data, logic_op):
        if isinstance(data, dict):
            for cond_op, fields in data.items():
                if (cond_op in self.accepted_cond_ops):
                    self._iterate_fields(fields, logic_op, cond_op)
                else:
                    self.module.fail(
                        msg='Supported conditions: {0}'.format(
                            str(self.condition_operator.keys())
                        )
                    )
        else:
            self.module.fail(msg='Supported conditions: {0}'.format(
                str(self.condition_operator.keys())))

    def _iterate_operators(self, data):
        if isinstance(data, dict):
            for logic_op, cond_op in data.items():
                if (logic_op in self.logic_operators):
                    self.simple_query = False
                    self._iterate_conditions(cond_op, logic_op)
                elif self.simple_query:
                    self.condition_operator['equals'](
                        'equals', logic_op, cond_op)
                    break
                else:
                    self.module.fail(msg='Query is not in a supported format')
        else:
            self.module.fail(
                msg='Supported operators: {0}'.format(
                    str(self.logic_operators)
                )
            )

    def _sort_key(self, e):
        if self.order_by in e.keys():
            return self.order_by
        else:
            prog = re.compile(r'.*' + self.order_by + r'.*')
            for key in e.keys():
                if prog.match(key):
                    return key
            return None

    def execute(self):
        try:
            response = self.table.get(
                query=self.query,
                limit=self.max_records,
                fields=self.return_fields)
        except Exception as detail:
            self.module.fail(
                msg='Failed to find record: {0}'.format(to_native(detail))
            )

        rlist = response.all()
        if len(rlist) > 0:
            self.order_by = self._sort_key(rlist[0])
        if self.order_by is not None:
            self.module.result['record'] = sorted(
                rlist,
                key=lambda x: x[self.order_by],
                reverse=self.reverse)
        else:
            self.module.result['record'] = rlist

        self.module.exit()


def main():
    # define the available arguments/parameters that a user can pass to
    # the module
    module_args = ServiceNowModule.create_argument_spec()
    module_args.update(
        table=dict(
            type='str',
            default='incident'
        ),
        query=dict(
            type='dict',
            required=True
        ),
        max_records=dict(
            type='int',
            default=20
        ),
        display_value=dict(
            type='bool',
            default=False
        ),
        exclude_reference_link=dict(
            type='bool',
            default=False
        ),
        suppress_pagination_header=dict(
            type='bool',
            default=False
        ),
        order_by=dict(
            type='str',
            default='-created_on'
        ),
        return_fields=dict(
            type='list',
            elements='str',
            default=[]
        )
    )

    module = ServiceNowModule(
        argument_spec=module_args,
        supports_check_mode=True,
    )

    query = SnowRecordFind(module)
    query.execute()


if __name__ == '__main__':
    main()

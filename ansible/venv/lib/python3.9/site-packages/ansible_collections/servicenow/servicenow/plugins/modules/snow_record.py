#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Ansible Project
# Copyright: (c) 2017, Tim Rightnour <thegarbledone@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: snow_record
short_description: Manage records in ServiceNow
description:
    - Creates, deletes and updates a single record in ServiceNow.
options:
    table:
      description:
      - Table to query for records.
      required: false
      default: incident
      type: str
    state:
      description:
      - If C(present) is supplied with a C(number) argument, the module will attempt to update the record with the supplied data.
      - If no such record exists, a new one will be created.
      - C(absent) will delete a record.
      choices: [ present, absent ]
      required: true
      type: str
    data:
      description:
      - key, value pairs of data to load into the record. See Examples.
      - Required for C(state:present).
      type: dict
    number:
      description:
      - Record number to update.
      - Required for C(state:absent).
      required: false
      type: str
    lookup_field:
      description:
      - Changes the field that C(number) uses to find records.
      required: false
      default: number
      type: str
    attachment:
      description:
      - Attach a file to the record.
      required: false
      type: str
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
requirements:
    - python pysnow (pysnow)
    - python requests (requests)
author:
    - Tim Rightnour (@garbled1)
extends_documentation_fragment:
- servicenow.servicenow.service_now.documentation

'''

EXAMPLES = r'''
- name: Grab a user record
  servicenow.servicenow.snow_record:
    username: ansible_test
    password: my_password
    instance: dev99999
    state: present
    number: 62826bf03710200044e0bfc8bcbe5df1
    table: sys_user
    lookup_field: sys_id

- name: Grab a user record, explicitly using basic authentication and suppress exceptions if not found
  servicenow.servicenow.snow_record:
    auth: basic
    raise_on_empty: False
    username: ansible_test
    password: my_password
    instance: dev99999
    state: present
    number: 62826bf03710200044e0bfc8bcbe5df1
    table: sys_user
    lookup_field: sys_id

- name: Grab a user record using OAuth
  servicenow.servicenow.snow_record:
    auth: oauth
    username: ansible_test
    password: my_password
    client_id: "1234567890abcdef1234567890abcdef"
    client_secret: "Password1!"
    instance: dev99999
    state: present
    number: 62826bf03710200044e0bfc8bcbe5df1
    table: sys_user
    lookup_field: sys_id

- name: Grab a user record using a bearer token
  servicenow.servicenow.snow_record:
    auth: token
    username: ansible_test
    password: my_password
    token: "y0urHorrend0u51yL0ngT0kenG0esH3r3..."
    instance: dev99999
    state: present
    number: 62826bf03710200044e0bfc8bcbe5df1
    table: sys_user
    lookup_field: sys_id

- name: Grab a user record using OpenID
  servicenow.servicenow.snow_record:
    auth: openid
    username: ansible_test
    password: my_password
    client_id: "1234567890abcdef1234567890abcdef"
    client_secret: "Password1!"
    openid_issuer: "https://yourorg.oktapreview.com/TH151s50meL0ngSTr1NG"
    openid_scope: "openid email"
    instance: dev99999
    state: present
    number: 62826bf03710200044e0bfc8bcbe5df1
    table: sys_user
    lookup_field: sys_id
  register: response

- name: Grab another user record using previous OpenID response
  servicenow.servicenow.snow_record:
    auth: openid
    username: ansible_test
    password: my_password
    client_id: "1234567890abcdef1234567890abcdef"
    client_secret: "Password1!"
    openid: "{{ response['openid'] }}"
    instance: dev99999
    state: present
    number: 62826bf03710200044e0bfc8deadbeef
    table: sys_user
    lookup_field: sys_id
  register: response

- name: Create an incident
  servicenow.servicenow.snow_record:
    username: ansible_test
    password: my_password
    instance: dev99999
    state: present
    data:
      short_description: "This is a test incident opened by Ansible"
      severity: 3
      priority: 2
  register: new_incident

- name: Create an incident using host instead of instance
  servicenow.servicenow.snow_record:
    username: ansible_test
    password: my_password
    host: dev99999.mycustom.domain.com
    state: present
    data:
      short_description: "This is a test incident opened by Ansible"
      priority: 2

- name: Delete the record we just made
  servicenow.servicenow.snow_record:
    username: admin
    password: xxxxxxx
    instance: dev99999
    state: absent
    number: "{{new_incident['record']['number']}}"

- name: Delete a non-existant record
  servicenow.servicenow.snow_record:
    username: ansible_test
    password: my_password
    instance: dev99999
    state: absent
    number: 9872354
  failed_when: false

- name: Update an incident
  servicenow.servicenow.snow_record:
    username: ansible_test
    password: my_password
    instance: dev99999
    state: present
    number: INC0000055
    data:
      work_notes : "Been working all day on this thing."

- name: Attach a file to an incident
  servicenow.servicenow.snow_record:
    username: ansible_test
    password: my_password
    instance: dev99999
    state: present
    number: INC0000055
    attachment: README.md
  tags: attach
'''

RETURN = r'''
record:
   description: Record data from Service Now
   type: dict
   returned: when supported
attached_file:
   description: Details of the file that was attached via C(attachment)
   type: dict
   returned: when supported
'''

import os
from ansible_collections.servicenow.servicenow.plugins.module_utils.service_now import ServiceNowModule
from ansible.module_utils._text import to_bytes, to_native

try:
    # This is being handled by ServiceNowModule
    import pysnow
    import requests
except ImportError:
    pass


def main():
    # define the available arguments/parameters that a user can pass to
    # the module
    module_args = ServiceNowModule.create_argument_spec()
    module_args.update(
        table=dict(
            type='str',
            default='incident'
        ),
        state=dict(
            type='str',
            required=True,
            choices=[
                'present',
                'absent'
            ],
        ),
        number=dict(
            type='str',
            default=None
        ),
        data=dict(
            type='dict',
            default=None
        ),
        lookup_field=dict(
            type='str',
            default='number'
        ),
        attachment=dict(
            type='str',
            default=None
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
        )
    )
    module_required_if = [
        ['state', 'absent', ['number']],
    ]

    module = ServiceNowModule(
        argument_spec=module_args,
        supports_check_mode=True,
        required_if=module_required_if,
    )

    params = module.params
    table = params['table']
    state = params['state']
    number = params['number']
    data = params['data']
    lookup_field = params['lookup_field']
    display_value = params['display_value']
    exclude_reference_link = params['exclude_reference_link']
    suppress_pagination_header = params['suppress_pagination_header']

    # check for attachments
    if params['attachment'] is not None:
        attach = params['attachment']
        b_attach = to_bytes(attach, errors='surrogate_or_strict')
        if not os.path.exists(b_attach):
            module.fail(msg="Attachment {0} not found".format(attach))
        module.result['attachment'] = attach
    else:
        attach = None

    module.connection.parameters.display_value = display_value
    module.connection.parameters.exclude_reference_link = exclude_reference_link
    module.connection.parameters.suppress_pagination_header = suppress_pagination_header

    # Deal with check mode
    if module.check_mode:

        # if we are in check mode and have no number, we would have created
        # a record.  We can only partially simulate this
        if number is None:
            module.result['record'] = dict(data)
            module.result['changed'] = True

        # do we want to check if the record is non-existent?
        elif state == 'absent':
            try:
                resource = module.connection.resource(
                    api_path='/table/' + table)
                response = resource.get(query={lookup_field: number})
                res = response.one()
                module.result['record'] = dict(Success=True)
                module.result['changed'] = True
            except pysnow.exceptions.NoResults:
                module.result['record'] = None
            except Exception as detail:
                module.fail(msg="Unknown failure in query record: {0}".format(
                    to_native(detail)
                )
                )

        # Let's simulate modification
        else:
            try:
                resource = module.connection.resource(
                    api_path='/table/' + table)
                response = resource.get(query={lookup_field: number})
                res = response.one()
                for key, value in data.items():
                    res[key] = value
                    module.result['changed'] = True
                module.result['record'] = res
            except pysnow.exceptions.NoResults:
                module.fail_json(msg="Record does not exist")
            except Exception as detail:
                module.fail(msg="Unknown failure in query record: {0}".format(
                    to_native(detail)
                )
                )
        module.exit()

    # now for the real thing: (non-check mode)

    # are we creating a new record?
    if state == 'present' and number is None:
        try:
            resource = module.connection.resource(api_path='/table/' + table)
            response = resource.create(payload=dict(data))
            record = response.one()
        except pysnow.exceptions.UnexpectedResponseFormat as e:
            module.fail(msg="Failed to create record: {0}, details: {1}".format(
                e.error_summary,
                e.error_details
            )
            )
        except pysnow.legacy_exceptions.UnexpectedResponse as e:
            module.fail(msg="Failed to create record due to %s" % to_native(e))
        module.result['record'] = record
        module.result['changed'] = True

    # we are deleting a record
    elif state == 'absent':
        try:
            resource = module.connection.resource(api_path='/table/' + table)
            res = resource.delete(query={lookup_field: number})
        except pysnow.exceptions.NoResults:
            res = dict(Success=True)
        except pysnow.exceptions.MultipleResults:
            module.fail(msg="Multiple record match")
        except pysnow.exceptions.UnexpectedResponseFormat as e:
            module.fail(msg="Failed to delete record: {0}, details: {1}".format(
                e.error_summary,
                e.error_details
            )
            )
        except pysnow.legacy_exceptions.UnexpectedResponse as e:
            module.fail(msg="Failed to delete record due to %s" % to_native(e))
        except Exception as detail:
            module.fail_json(msg="Failed to delete record: {0}".format(
                to_native(detail)
            )
            )
        module.result['record'] = res
        module.result['changed'] = True

    # We want to update a record
    else:
        try:
            resource = module.connection.resource(api_path='/table/' + table)
            response = resource.get(query={lookup_field: number})
            record = response.one()
            if data is not None:
                res = response.update(data)
                record = res.one()
                module.result['record'] = record
                module.result['changed'] = True
            else:
                module.result['record'] = record
            if attach is not None:
                res = response.upload(b_attach)
                module.result['changed'] = True
                module.result['attached_file'] = res

        except pysnow.exceptions.MultipleResults:
            module.fail(msg="Multiple record match")
        except pysnow.exceptions.NoResults:
            module.fail(msg="Record does not exist")
        except pysnow.exceptions.UnexpectedResponseFormat as e:
            snow_error = "Failed to update record: {0}, details: {1}".format(
                e.error_summary,
                e.error_details
            )
            module.fail(msg=snow_error)
        except pysnow.legacy_exceptions.UnexpectedResponse as e:
            module.fail(
                msg="Failed to update record due to %s" % to_native(e)
            )
        except Exception as detail:
            module.fail(msg="Failed to update record: {0}".format(
                to_native(detail)
            )
            )

    module.exit()


if __name__ == '__main__':
    main()

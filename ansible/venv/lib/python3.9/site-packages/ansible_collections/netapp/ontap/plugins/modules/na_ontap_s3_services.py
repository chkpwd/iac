#!/usr/bin/python

# (c) 2018-2022, NetApp, Inc
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = '''
module: na_ontap_s3_services
short_description: NetApp ONTAP S3 services
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: 21.20.0
author: NetApp Ansible Team (@carchi8py) <ng-ansibleteam@netapp.com>
description:
- Create, delete or modify S3 Service

options:
  state:
    description:
    - Whether the specified S3 bucket should exist or not.
    choices: ['present', 'absent']
    type: str
    default: 'present'

  name:
    description:
    - The name of the S3 service.
    type: str
    required: true

  vserver:
    description:
    - Name of the vserver to use.
    type: str
    required: true

  enabled:
    description:
    - enable or disable the service
    type: bool

  comment:
    description:
    - comment about the service
    type: str

  certificate_name:
    description:
    - name of https certificate to use for the service
    type: str
'''

EXAMPLES = """
    - name: create or modify s3 service
      na_ontap_s3_services:
        state: present
        name: carchi-test
        vserver: ansibleSVM
        comment: not enabled
        enabled: False
        certificate_name: ansibleSVM_16E1C1284D889609
        hostname: "{{ netapp_hostname }}"
        username: "{{ netapp_username }}"
        password: "{{ netapp_password }}"
        https: true
        validate_certs: false
        use_rest: always

    - name: delete s3 service
      na_ontap_s3_services:
        state: absent
        name: carchi-test
        vserver: ansibleSVM
        certificate_name: ansibleSVM_16E1C1284D889609
        hostname: "{{ netapp_hostname }}"
        username: "{{ netapp_username }}"
        password: "{{ netapp_password }}"
        https: true
        validate_certs: false
        use_rest: always
"""


RETURN = """
"""

import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppOntapS3Services:
    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            name=dict(required=True, type='str'),
            enabled=dict(required=False, type='bool'),
            vserver=dict(required=True, type='str'),
            comment=dict(required=False, type='str'),
            certificate_name=dict(required=False, type='str'),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )
        self.svm_uuid = None
        self.na_helper = NetAppModule(self.module)
        self.parameters = self.na_helper.check_and_set_parameters(self.module)

        self.rest_api = OntapRestAPI(self.module)
        partially_supported_rest_properties = []  # TODO: Remove if there nothing here
        self.use_rest = self.rest_api.is_rest(partially_supported_rest_properties=partially_supported_rest_properties,
                                              parameters=self.parameters)

        self.rest_api.fail_if_not_rest_minimum_version('na_ontap_s3_services', 9, 8)

    def get_s3_service(self):
        api = 'protocols/s3/services'
        fields = ','.join(('name',
                           'enabled',
                           'svm.uuid',
                           'comment',
                           'certificate.name'))

        params = {
            'name': self.parameters['name'],
            'svm.name': self.parameters['vserver'],
            'fields': fields
        }
        record, error = rest_generic.get_one_record(self.rest_api, api, params)
        if error:
            self.module.fail_json(msg='Error fetching S3 service %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())
        if record:
            if self.na_helper.safe_get(record, ['certificate', 'name']):
                record['certificate_name'] = self.na_helper.safe_get(record, ['certificate', 'name'])
            return self.set_uuids(record)
        return None

    def create_s3_service(self):
        api = 'protocols/s3/services'
        body = {'svm.name': self.parameters['vserver'], 'name': self.parameters['name']}
        if self.parameters.get('enabled') is not None:
            body['enabled'] = self.parameters['enabled']
        if self.parameters.get('comment'):
            body['comment'] = self.parameters['comment']
        if self.parameters.get('certificate_name'):
            body['certificate.name'] = self.parameters['certificate_name']
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error:
            self.module.fail_json(msg='Error creating S3 service %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def delete_s3_service(self):
        api = 'protocols/s3/services'
        # The rest default is to delete all users, and empty bucket attached to a service.
        # This would not be idempotent, so switching this to False.
        # second issue, delete_all: True will say it deleted, but the ONTAP system will show it's still there until the job for the
        # delete buckets/users/groups is complete.
        body = {'delete_all': False}
        dummy, error = rest_generic.delete_async(self.rest_api, api, self.svm_uuid, body=body)
        if error:
            self.module.fail_json(msg='Error deleting S3 service %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def modify_s3_service(self, modify):
        # Once the service is created, bucket and user can not be modified by the service api, but only the user/group/bucket modules
        api = 'protocols/s3/services'
        body = {'name': self.parameters['name']}
        if modify.get('enabled') is not None:
            body['enabled'] = self.parameters['enabled']
        if modify.get('comment'):
            body['comment'] = self.parameters['comment']
        if modify.get('certificate_name'):
            body['certificate.name'] = self.parameters['certificate_name']
        dummy, error = rest_generic.patch_async(self.rest_api, api, self.svm_uuid, body)
        if error:
            self.module.fail_json(msg='Error modifying S3 service %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def set_uuids(self, record):
        self.svm_uuid = record['svm']['uuid']
        return record

    def apply(self):
        current = self.get_s3_service()
        cd_action, modify = None, None
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action is None:
            modify = self.na_helper.get_modified_attributes(current, self.parameters)
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_s3_service()
            if cd_action == 'delete':
                self.delete_s3_service()
            if modify:
                self.modify_s3_service(modify)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    '''Apply volume operations from playbook'''
    obj = NetAppOntapS3Services()
    obj.apply()


if __name__ == '__main__':
    main()

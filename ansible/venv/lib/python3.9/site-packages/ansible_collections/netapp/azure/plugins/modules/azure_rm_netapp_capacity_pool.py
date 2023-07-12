#!/usr/bin/python
#
# (c) 2019, NetApp, Inc
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
azure_rm_netapp_capacity_pool
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: azure_rm_netapp_capacity_pool

short_description: Manage NetApp Azure Files capacity pool
version_added: 19.10.0
author: NetApp Ansible Team (@carchi8py) <ng-ansibleteam@netapp.com>

description:
    - Create and delete NetApp Azure capacity pool.
      Provide the Resource group name for the capacity pool to be created.
    - Resize NetApp Azure capacity pool
extends_documentation_fragment:
    - netapp.azure.azure
    - netapp.azure.azure_tags
    - netapp.azure.netapp.azure_rm_netapp

options:
    name:
        description:
            - The name of the capacity pool.
        required: true
        type: str
    account_name:
        description:
            - The name of the NetApp account.
        required: true
        type: str
    location:
        description:
            - Resource location.
            - Required for create.
        type: str
    size:
        description:
            - Provisioned size of the pool (in chunks). Allowed values are in 4TiB chunks.
            - Provide number to be multiplied to 4TiB.
            - Required for create.
        default: 1
        type: int
    service_level:
        description:
            - The service level of the file system.
            - Required for create.
        choices: ['Standard', 'Premium', 'Ultra']
        type: str
        version_added: "20.5.0"
    state:
        description:
            - State C(present) will check that the capacity pool exists with the requested configuration.
            - State C(absent) will delete the capacity pool.
        default: present
        choices: ['present', 'absent']
        type: str

'''
EXAMPLES = '''

- name: Create Azure NetApp capacity pool
  netapp.azure.azure_rm_netapp_capacity_pool:
    resource_group: myResourceGroup
    account_name: tests-netapp
    name: tests-pool
    location: eastus
    size: 2
    service_level: Standard

- name: Resize Azure NetApp capacity pool
  netapp.azure.azure_rm_netapp_capacity_pool:
    resource_group: myResourceGroup
    account_name: tests-netapp
    name: tests-pool
    location: eastus
    size: 3
    service_level: Standard

- name: Delete Azure NetApp capacity pool
  netapp.azure.azure_rm_netapp_capacity_pool:
    state: absent
    resource_group: myResourceGroup
    account_name: tests-netapp
    name: tests-pool

'''

RETURN = '''
'''

import traceback

AZURE_OBJECT_CLASS = 'NetAppAccount'
HAS_AZURE_MGMT_NETAPP = False
IMPORT_ERRORS = list()
SIZE_POOL = 4398046511104

try:
    from msrestazure.azure_exceptions import CloudError
    from azure.core.exceptions import AzureError, ResourceNotFoundError
except ImportError as exc:
    IMPORT_ERRORS.append(str(exc))

try:
    from azure.mgmt.netapp.models import CapacityPool
    HAS_AZURE_MGMT_NETAPP = True
except ImportError as exc:
    IMPORT_ERRORS.append(str(exc))

from ansible.module_utils.basic import to_native
from ansible_collections.netapp.azure.plugins.module_utils.azure_rm_netapp_common import AzureRMNetAppModuleBase
from ansible_collections.netapp.azure.plugins.module_utils.netapp_module import NetAppModule


class AzureRMNetAppCapacityPool(AzureRMNetAppModuleBase):
    """ create, modify, delete a capacity pool """
    def __init__(self):

        self.module_arg_spec = dict(
            resource_group=dict(type='str', required=True),
            name=dict(type='str', required=True),
            account_name=dict(type='str', required=True),
            location=dict(type='str', required=False),
            state=dict(choices=['present', 'absent'], default='present', type='str'),
            size=dict(type='int', required=False, default=1),
            service_level=dict(type='str', required=False, choices=['Standard', 'Premium', 'Ultra']),
        )

        self.na_helper = NetAppModule()
        self.parameters = dict()

        # import errors are handled in AzureRMModuleBase
        super(AzureRMNetAppCapacityPool, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                        required_if=[('state', 'present', ['location', 'service_level'])],
                                                        supports_check_mode=True)

    def get_azure_netapp_capacity_pool(self):
        """
            Returns capacity pool object for an existing pool
            Return None if capacity pool does not exist
        """
        try:
            capacity_pool_get = self.netapp_client.pools.get(self.parameters['resource_group'],
                                                             self.parameters['account_name'], self.parameters['name'])
        except (CloudError, ResourceNotFoundError):  # capacity pool does not exist
            return None
        return capacity_pool_get

    def create_azure_netapp_capacity_pool(self):
        """
            Create a capacity pool for the given Azure NetApp Account
            :return: None
        """
        options = self.na_helper.get_not_none_values_from_dict(self.parameters, ['location', 'service_level', 'size', 'tags'])
        capacity_pool_body = CapacityPool(**options)
        try:
            response = self.get_method('pools', 'create_or_update')(body=capacity_pool_body, resource_group_name=self.parameters['resource_group'],
                                                                    account_name=self.parameters['account_name'],
                                                                    pool_name=self.parameters['name'])
            while response.done() is not True:
                response.result(10)

        except (CloudError, AzureError) as error:
            self.module.fail_json(msg='Error creating capacity pool %s for Azure NetApp account %s: %s'
                                  % (self.parameters['name'], self.parameters['account_name'], to_native(error)),
                                  exception=traceback.format_exc())

    def modify_azure_netapp_capacity_pool(self, modify):
        """
            Modify a capacity pool for the given Azure NetApp Account
            :return: None
        """
        options = self.na_helper.get_not_none_values_from_dict(self.parameters, ['location', 'service_level', 'size', 'tags'])
        capacity_pool_body = CapacityPool(**options)
        try:
            response = self.get_method('pools', 'update')(body=capacity_pool_body, resource_group_name=self.parameters['resource_group'],
                                                          account_name=self.parameters['account_name'],
                                                          pool_name=self.parameters['name'])
            while response.done() is not True:
                response.result(10)

        except (CloudError, AzureError) as error:
            self.module.fail_json(msg='Error modifying capacity pool %s for Azure NetApp account %s: %s'
                                  % (self.parameters['name'], self.parameters['account_name'], to_native(error)),
                                  exception=traceback.format_exc())

    def delete_azure_netapp_capacity_pool(self):
        """
            Delete a capacity pool for the given Azure NetApp Account
            :return: None
        """
        try:
            response = self.get_method('pools', 'delete')(resource_group_name=self.parameters['resource_group'],
                                                          account_name=self.parameters['account_name'], pool_name=self.parameters['name'])
            while response.done() is not True:
                response.result(10)

        except (CloudError, AzureError) as error:
            self.module.fail_json(msg='Error deleting capacity pool %s for Azure NetApp account %s: %s'
                                  % (self.parameters['name'], self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def exec_module(self, **kwargs):

        # unlikely
        self.fail_when_import_errors(IMPORT_ERRORS, HAS_AZURE_MGMT_NETAPP)

        # set up parameters according to our initial list
        for key in list(self.module_arg_spec):
            self.parameters[key] = kwargs[key]
        # and common parameter
        for key in ['tags']:
            if key in kwargs:
                self.parameters[key] = kwargs[key]
        if 'size' in self.parameters:
            self.parameters['size'] *= SIZE_POOL

        modify = {}
        current = self.get_azure_netapp_capacity_pool()
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action is None and self.parameters['state'] == 'present':
            current = vars(current)
            # get_azure_netapp_capacity_pool() returns pool name with account name appended in front of it like 'account/pool'
            current['name'] = self.parameters['name']
            modify = self.na_helper.get_modified_attributes(current, self.parameters)
            if 'tags' in modify:
                dummy, modify['tags'] = self.update_tags(current.get('tags'))

        if self.na_helper.changed:
            if self.module.check_mode:
                pass
            else:
                if cd_action == 'create':
                    self.create_azure_netapp_capacity_pool()
                elif cd_action == 'delete':
                    self.delete_azure_netapp_capacity_pool()
                elif modify:
                    self.modify_azure_netapp_capacity_pool(modify)

        self.module.exit_json(changed=self.na_helper.changed, modify=modify)


def main():
    AzureRMNetAppCapacityPool()


if __name__ == '__main__':
    main()

#!/usr/bin/python
#
# (c) 2019, NetApp, Inc
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
azure_rm_netapp_snapshot
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: azure_rm_netapp_snapshot

short_description: Manage NetApp Azure Files Snapshot
version_added: 19.10.0
author: NetApp Ansible Team (@carchi8py) <ng-ansibleteam@netapp.com>

description:
    - Create and delete NetApp Azure Snapshot.
extends_documentation_fragment:
    - netapp.azure.azure
    - netapp.azure.netapp.azure_rm_netapp

options:
    name:
        description:
            - The name of the snapshot.
        required: true
        type: str
    volume_name:
        description:
            - The name of the volume.
        required: true
        type: str
    pool_name:
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
    state:
        description:
            - State C(present) will check that the snapshot exists with the requested configuration.
            - State C(absent) will delete the snapshot.
        default: present
        choices:
            - absent
            - present
        type: str

'''
EXAMPLES = '''

- name: Create Azure NetApp Snapshot
  netapp.azure.azure_rm_netapp_snapshot:
    resource_group: myResourceGroup
    account_name: tests-netapp
    pool_name: tests-pool
    volume_name: tests-volume2
    name: tests-snapshot
    location: eastus

- name: Delete Azure NetApp Snapshot
  netapp.azure.azure_rm_netapp_snapshot:
    state: absent
    resource_group: myResourceGroup
    account_name: tests-netapp
    pool_name: tests-pool
    volume_name: tests-volume2
    name: tests-snapshot

'''

RETURN = '''
'''

import traceback

AZURE_OBJECT_CLASS = 'NetAppAccount'
HAS_AZURE_MGMT_NETAPP = False
IMPORT_ERRORS = list()

try:
    from msrestazure.azure_exceptions import CloudError
    from azure.core.exceptions import AzureError, ResourceNotFoundError
except ImportError as exc:
    IMPORT_ERRORS.append(str(exc))

try:
    from azure.mgmt.netapp.models import Snapshot
    HAS_AZURE_MGMT_NETAPP = True
except ImportError as exc:
    IMPORT_ERRORS.append(str(exc))

from ansible.module_utils.basic import to_native
from ansible_collections.netapp.azure.plugins.module_utils.azure_rm_netapp_common import AzureRMNetAppModuleBase
from ansible_collections.netapp.azure.plugins.module_utils.netapp_module import NetAppModule


class AzureRMNetAppSnapshot(AzureRMNetAppModuleBase):
    """ crate or delete snapshots """
    def __init__(self):

        self.module_arg_spec = dict(
            resource_group=dict(type='str', required=True),
            name=dict(type='str', required=True),
            volume_name=dict(type='str', required=True),
            pool_name=dict(type='str', required=True),
            account_name=dict(type='str', required=True),
            location=dict(type='str', required=False),
            state=dict(choices=['present', 'absent'], default='present', type='str')
        )
        self.na_helper = NetAppModule()
        self.parameters = dict()

        # import errors are handled in AzureRMModuleBase
        super(AzureRMNetAppSnapshot, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                    required_if=[('state', 'present', ['location'])],
                                                    supports_check_mode=True,
                                                    supports_tags=False)

    def get_azure_netapp_snapshot(self):
        """
            Returns snapshot object for an existing snapshot
            Return None if snapshot does not exist
        """
        try:
            snapshot_get = self.netapp_client.snapshots.get(self.parameters['resource_group'], self.parameters['account_name'],
                                                            self.parameters['pool_name'], self.parameters['volume_name'],
                                                            self.parameters['name'])
        except (CloudError, ResourceNotFoundError):  # snapshot does not exist
            return None
        return snapshot_get

    def create_azure_netapp_snapshot(self):
        """
            Create a snapshot for the given Azure NetApp Account
            :return: None
        """
        kw_args = dict(
            resource_group_name=self.parameters['resource_group'],
            account_name=self.parameters['account_name'],
            pool_name=self.parameters['pool_name'],
            volume_name=self.parameters['volume_name'],
            snapshot_name=self.parameters['name']
        )
        if self.new_style:
            kw_args['body'] = Snapshot(
                location=self.parameters['location']
            )
        else:
            kw_args['location'] = self.parameters['location']
        try:
            result = self.get_method('snapshots', 'create')(**kw_args)
            # waiting till the status turns Succeeded
            while result.done() is not True:
                result.result(10)

        except (CloudError, AzureError) as error:
            self.module.fail_json(msg='Error creating snapshot %s for Azure NetApp account %s: %s'
                                  % (self.parameters['name'], self.parameters['account_name'], to_native(error)),
                                  exception=traceback.format_exc())

    def delete_azure_netapp_snapshot(self):
        """
            Delete a snapshot for the given Azure NetApp Account
            :return: None
        """
        try:
            result = self.get_method('snapshots', 'delete')(resource_group_name=self.parameters['resource_group'],
                                                            account_name=self.parameters['account_name'],
                                                            pool_name=self.parameters['pool_name'],
                                                            volume_name=self.parameters['volume_name'],
                                                            snapshot_name=self.parameters['name'])
            # waiting till the status turns Succeeded
            while result.done() is not True:
                result.result(10)

        except (CloudError, AzureError) as error:
            self.module.fail_json(msg='Error deleting snapshot %s for Azure NetApp account %s: %s'
                                  % (self.parameters['name'], self.parameters['account_name'], to_native(error)),
                                  exception=traceback.format_exc())

    def exec_module(self, **kwargs):

        # unlikely
        self.fail_when_import_errors(IMPORT_ERRORS, HAS_AZURE_MGMT_NETAPP)

        # set up parameters according to our initial list
        for key in list(self.module_arg_spec):
            self.parameters[key] = kwargs[key]

        current = self.get_azure_netapp_snapshot()
        cd_action = self.na_helper.get_cd_action(current, self.parameters)

        if self.na_helper.changed:
            if self.module.check_mode:
                pass
            else:
                if cd_action == 'create':
                    self.create_azure_netapp_snapshot()
                elif cd_action == 'delete':
                    self.delete_azure_netapp_snapshot()

        self.module.exit_json(changed=self.na_helper.changed)


def main():
    AzureRMNetAppSnapshot()


if __name__ == '__main__':
    main()

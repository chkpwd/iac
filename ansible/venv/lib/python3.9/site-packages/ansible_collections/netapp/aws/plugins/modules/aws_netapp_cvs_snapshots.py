#!/usr/bin/python

# (c) 2019, NetApp Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""AWS Cloud Volumes Services - Manage Snapshots"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''

module: aws_netapp_cvs_snapshots

short_description: NetApp AWS Cloud Volumes Service Manage Snapshots.
extends_documentation_fragment:
    - netapp.aws.netapp.awscvs
version_added: 2.9.0
author: NetApp Ansible Team (@carchi8py) <ng-ansibleteam@netapp.com>
description:
- Create, Update, Delete Snapshot on AWS Cloud Volumes Service.

options:
  state:
     description:
     - Whether the specified snapshot should exist or not.
     required: true
     type: str
     choices: ['present', 'absent']

  region:
    description:
    - The region to which the snapshot belongs to.
    required: true
    type: str

  name:
    description:
    - Name of the snapshot
    required: true
    type: str

  fileSystemId:
    description:
    - Name or Id of the filesystem.
    - Required for create operation
    type: str

  from_name:
    description:
    - ID or Name of the snapshot to rename.
    - Required to create an snapshot called 'name' by renaming 'from_name'.
    type: str
'''

EXAMPLES = """
- name: Create Snapshot
  aws_netapp_cvs_snapshots:
    state: present
    region: us-east-1
    name: testSnapshot
    fileSystemId: testVolume
    api_url : cds-aws-bundles.netapp.com
    api_key: myApiKey
    secret_key : mySecretKey

- name: Update Snapshot
  aws_netapp_cvs_snapshots:
    state: present
    region: us-east-1
    name: testSnapshot - renamed
    from_name: testSnapshot
    fileSystemId: testVolume
    api_url : cds-aws-bundles.netapp.com
    api_key: myApiKey
    secret_key : mySecretKey

- name: Delete Snapshot
  aws_netapp_cvs_snapshots:
    state: absent
    region: us-east-1
    name: testSnapshot
    api_url : cds-aws-bundles.netapp.com
    api_key: myApiKey
    secret_key : mySecretKey
"""

RETURN = """
"""

from ansible.module_utils.basic import AnsibleModule
import ansible_collections.netapp.aws.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.aws.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.aws.plugins.module_utils.netapp import AwsCvsRestAPI


class AwsCvsNetappSnapshot(object):
    """
    Contains methods to parse arguments,
    derive details of AWS_CVS objects
    and send requests to AWS CVS via
    the restApi
    """

    def __init__(self):
        """
        Parse arguments, setup state variables,
        check paramenters and ensure request module is installed
        """
        self.argument_spec = netapp_utils.aws_cvs_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=True, choices=['present', 'absent']),
            region=dict(required=True, type='str'),
            name=dict(required=True, type='str'),
            from_name=dict(required=False, type='str'),
            fileSystemId=dict(required=False, type='str')
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_if=[
                ('state', 'present', ['fileSystemId']),
            ],
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()

        # set up state variables
        self.parameters = self.na_helper.set_parameters(self.module.params)
        # Calling generic AWSCVS restApi class
        self.rest_api = AwsCvsRestAPI(self.module)

        # Checking for the parameters passed and create new parameters list
        self.data = {}
        for key in self.parameters.keys():
            self.data[key] = self.parameters[key]

    def get_snapshot_id(self, name):
        # Check if  snapshot exists
        # Return snpashot Id  If Snapshot is found, None otherwise
        list_snapshots, error = self.rest_api.get('Snapshots')

        if error:
            self.module.fail_json(msg=error)

        for snapshot in list_snapshots:
            if snapshot['name'] == name:
                return snapshot['snapshotId']
        return None

    def get_filesystem_id(self):
        # Check given FileSystem is exists
        # Return fileSystemId is found, None otherwise
        list_filesystem, error = self.rest_api.get('FileSystems')

        if error:
            self.module.fail_json(msg=error)
        for filesystem in list_filesystem:
            if filesystem['fileSystemId'] == self.parameters['fileSystemId']:
                return filesystem['fileSystemId']
            elif filesystem['creationToken'] == self.parameters['fileSystemId']:
                return filesystem['fileSystemId']
        return None

    def create_snapshot(self):
        # Create Snapshot
        api = 'Snapshots'
        dummy, error = self.rest_api.post(api, self.data)
        if error:
            self.module.fail_json(msg=error)

    def rename_snapshot(self, snapshot_id):
        # Rename Snapshot
        api = 'Snapshots/' + snapshot_id
        dummy, error = self.rest_api.put(api, self.data)
        if error:
            self.module.fail_json(msg=error)

    def delete_snapshot(self, snapshot_id):
        # Delete Snapshot
        api = 'Snapshots/' + snapshot_id
        dummy, error = self.rest_api.delete(api, self.data)
        if error:
            self.module.fail_json(msg=error)

    def apply(self):
        """
        Perform pre-checks, call functions and exit
        """
        self.snapshot_id = self.get_snapshot_id(self.data['name'])

        if self.snapshot_id is None and 'fileSystemId' in self.data:
            self.filesystem_id = self.get_filesystem_id()
            self.data['fileSystemId'] = self.filesystem_id
            if self.filesystem_id is None:
                self.module.fail_json(msg='Error: Specified filesystem id %s does not exist ' % self.data['fileSystemId'])

        cd_action = self.na_helper.get_cd_action(self.snapshot_id, self.data)
        result_message = ""
        if self.na_helper.changed:
            if self.module.check_mode:
                # Skip changes
                result_message = "Check mode, skipping changes"
            else:
                if cd_action == "delete":
                    self.delete_snapshot(self.snapshot_id)
                    result_message = "Snapshot Deleted"

                elif cd_action == "create":
                    if 'from_name' in self.data:
                        # If cd_action is craete and from_name is given
                        snapshot_id = self.get_snapshot_id(self.data['from_name'])
                        if snapshot_id is not None:
                            # If resource pointed by from_name exists, rename the snapshot to name
                            self.rename_snapshot(snapshot_id)
                            result_message = "Snapshot Updated"
                        else:
                            # If resource pointed by from_name does not exists, error out
                            self.module.fail_json(msg="Resource does not exist : %s" % self.data['from_name'])
                    else:
                        self.create_snapshot()
                        # If from_name is not defined, Create from scratch.
                        result_message = "Snapshot Created"

        self.module.exit_json(changed=self.na_helper.changed, msg=result_message)


def main():
    """
    Main function
    """
    aws_netapp_cvs_snapshots = AwsCvsNetappSnapshot()
    aws_netapp_cvs_snapshots.apply()


if __name__ == '__main__':
    main()

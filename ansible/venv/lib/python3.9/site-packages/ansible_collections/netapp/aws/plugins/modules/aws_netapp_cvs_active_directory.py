#!/usr/bin/python

# (c) 2019, NetApp Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""AWS Cloud Volumes Services - Manage ActiveDirectory"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}


DOCUMENTATION = '''

module: aws_netapp_cvs_active_directory

short_description: NetApp AWS CloudVolumes Service Manage Active Directory.
extends_documentation_fragment:
    - netapp.aws.netapp.awscvs
version_added: 2.9.0
author: NetApp Ansible Team (@carchi8py) <ng-ansibleteam@netapp.com>
description:
    - Create, Update, Delete ActiveDirectory on AWS Cloud Volumes Service.

options:
  state:
     description:
         - Whether the specified ActiveDirectory should exist or not.
     choices: ['present', 'absent']
     required: true
     type: str

  region:
    description:
    - The region to which the Active Directory credentials are associated.
    required: true
    type: str

  domain:
    description:
    - Name of the Active Directory domain
    type: str

  DNS:
    description:
    - DNS server address for the Active Directory domain
    - Required when C(state=present)
    - Required when C(state=present), to modify ActiveDirectory properties.
    type: str

  netBIOS:
    description:
    - NetBIOS name of the server.
    type: str

  username:
    description:
    - Username of the Active Directory domain administrator
    type: str

  password:
    description:
    - Password of the Active Directory domain administrator
    - Required when C(state=present), to modify ActiveDirectory properties
    type: str
'''

EXAMPLES = """
    - name: Create Active Directory
      aws_netapp_cvs_active_directory.py:
        state: present
        region: us-east-1
        DNS: 101.102.103.123
        domain: mydomain.com
        password: netapp1!
        netBIOS: testing
        username: user1
        api_url : My_CVS_Hostname
        api_key: My_API_Key
        secret_key : My_Secret_Key

    - name: Update Active Directory
      aws_netapp_cvs_active_directory.py:
        state: present
        region: us-east-1
        DNS: 101.102.103.123
        domain: mydomain.com
        password: netapp2!
        netBIOS: testingBIOS
        username: user2
        api_url : My_CVS_Hostname
        api_key: My_API_Key
        secret_key : My_Secret_Key

    - name: Delete Active Directory
      aws_netapp_cvs_active_directory.py:
        state: absent
        region: us-east-1
        domain: mydomain.com
        api_url : My_CVS_Hostname
        api_key: My_API_Key
        secret_key : My_Secret_Key
"""

RETURN = '''
'''

from ansible.module_utils.basic import AnsibleModule
import ansible_collections.netapp.aws.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.aws.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.aws.plugins.module_utils.netapp import AwsCvsRestAPI


class AwsCvsNetappActiveDir(object):
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
            state=dict(required=True, choices=['present', 'absent'], type='str'),
            region=dict(required=True, type='str'),
            DNS=dict(required=False, type='str'),
            domain=dict(required=False, type='str'),
            password=dict(required=False, type='str', no_log=True),
            netBIOS=dict(required=False, type='str'),
            username=dict(required=False, type='str')
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_if=[
                ('state', 'present', ['domain', 'password']),
            ],
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()

        # set up state variables
        self.parameters = self.na_helper.set_parameters(self.module.params)
        # Calling generic AWSCVS restApi class
        self.rest_api = AwsCvsRestAPI(self.module)

    def get_activedirectory_id(self):
        # Check if  ActiveDirectory exists
        # Return UUID for ActiveDirectory is found, None otherwise
        try:
            list_activedirectory, error = self.rest_api.get('Storage/ActiveDirectory')
        except Exception:
            return None
        if error is not None:
            self.module.fail_json(msg='Error calling list_activedirectory: %s' % error)

        for activedirectory in list_activedirectory:
            if activedirectory['region'] == self.parameters['region']:
                return activedirectory['UUID']
        return None

    def get_activedirectory(self, activedirectory_id=None):
        if activedirectory_id is None:
            return None
        else:
            activedirectory_info, error = self.rest_api.get('Storage/ActiveDirectory/%s' % activedirectory_id)
            if not error:
                return activedirectory_info
            return None

    def create_activedirectory(self):
        # Create ActiveDirectory
        api = 'Storage/ActiveDirectory'
        data = {"region": self.parameters['region'], "DNS": self.parameters['DNS'], "domain": self.parameters['domain'],
                "username": self.parameters['username'], "password": self.parameters['password'], "netBIOS": self.parameters['netBIOS']}

        response, error = self.rest_api.post(api, data)

        if not error:
            return response
        else:
            self.module.fail_json(msg=response['message'])

    def delete_activedirectory(self):
        activedirectory_id = self.get_activedirectory_id()
        # Delete ActiveDirectory

        if activedirectory_id:
            api = 'Storage/ActiveDirectory/' + activedirectory_id
            data = None
            response, error = self.rest_api.delete(api, data)
            if not error:
                return response
            else:
                self.module.fail_json(msg=response['message'])

        else:
            self.module.fail_json(msg="Active Directory does not exist")

    def update_activedirectory(self, activedirectory_id, updated_activedirectory):
        # Update ActiveDirectory
        api = 'Storage/ActiveDirectory/' + activedirectory_id
        data = {
            "region": self.parameters['region'],
            "DNS": updated_activedirectory['DNS'],
            "domain": updated_activedirectory['domain'],
            "username": updated_activedirectory['username'],
            "password": updated_activedirectory['password'],
            "netBIOS": updated_activedirectory['netBIOS']
        }

        response, error = self.rest_api.put(api, data)
        if not error:
            return response
        else:
            self.module.fail_json(msg=response['message'])

    def apply(self):
        """
        Perform pre-checks, call functions and exit
        """
        modify = False
        activedirectory_id = self.get_activedirectory_id()
        current = self.get_activedirectory(activedirectory_id)
        cd_action = self.na_helper.get_cd_action(current, self.parameters)

        if current and self.parameters['state'] != 'absent':
            keys_to_check = ['DNS', 'domain', 'username', 'netBIOS']
            updated_active_directory, modify = self.na_helper.compare_and_update_values(current, self.parameters, keys_to_check)

            if self.parameters['password']:
                modify = True
                updated_active_directory['password'] = self.parameters['password']

            if modify is True:
                self.na_helper.changed = True
                if 'domain' in self.parameters and self.parameters['domain'] is not None:
                    ad_exists = self.get_activedirectory(updated_active_directory['domain'])
                    if ad_exists:
                        modify = False
                        self.na_helper.changed = False

        if self.na_helper.changed:
            if self.module.check_mode:
                pass
            else:
                if modify is True:
                    self.update_activedirectory(activedirectory_id, updated_active_directory)
                elif cd_action == 'create':
                    self.create_activedirectory()
                elif cd_action == 'delete':
                    self.delete_activedirectory()

        self.module.exit_json(changed=self.na_helper.changed)


def main():
    """
    Main function
    """
    aws_netapp_cvs_active_directory = AwsCvsNetappActiveDir()
    aws_netapp_cvs_active_directory.apply()


if __name__ == '__main__':
    main()

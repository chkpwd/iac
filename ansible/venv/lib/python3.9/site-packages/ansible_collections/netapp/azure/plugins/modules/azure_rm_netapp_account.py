#!/usr/bin/python
#
# (c) 2019, NetApp, Inc
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
azure_rm_netapp_account
'''

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: azure_rm_netapp_account

short_description: Manage NetApp Azure Files Account
version_added: 19.10.0
author: NetApp Ansible Team (@carchi8py) <ng-ansibleteam@netapp.com>

description:
    - Create and delete NetApp Azure account.
      Provide the Resource group name for the NetApp account to be created.
extends_documentation_fragment:
    - netapp.azure.azure
    - netapp.azure.azure_tags
    - netapp.azure.netapp.azure_rm_netapp

options:
    name:
        description:
            - The name of the NetApp account.
        required: true
        type: str
    location:
        description:
            - Resource location.
            - Required for create.
        type: str

    active_directories:
      description:
        - list of active directory dictionaries.
        - The list is currently limited to a single active directory (ANF or Azure limit of one AD per subscription).
      type: list
      elements: dict
      version_added: 21.2.0
      suboptions:
        active_directory_id:
          description: not used for create.  Not needed for join.
          type: str
        dns:
          description: list of DNS addresses.  Required for create or join.
          type: list
          elements: str
        domain:
          description: Fully Qualified Active Directory DNS Domain Name.  Required for create or join.
          type: str
        site:
          description: The Active Directory site the service will limit Domain Controller discovery to.
          type: str
        smb_server_name:
          description: Prefix for creating the SMB server's computer account name in the Active Directory domain.  Required for create or join.
          type: str
        organizational_unit:
          description: LDAP Path for the Organization Unit where SMB Server machine accounts will be created (i.e. OU=SecondLevel,OU=FirstLevel).
          type: str
        username:
          description: Credentials that have permissions to create SMB server machine account in the AD domain.  Required for create or join.
          type: str
        password:
          description: see username.  If password is present, the module is not idempotent, as we cannot check the current value.  Required for create or join.
          type: str
        aes_encryption:
          description: If enabled, AES encryption will be enabled for SMB communication.
          type: bool
        ldap_signing:
          description: Specifies whether or not the LDAP traffic needs to be signed.
          type: bool
        ad_name:
          description: Name of the active directory machine.  Used only while creating kerberos volume.
          type: str
          version_added: 21.3.0
        kdc_ip:
          description: kdc server IP addresses for the active directory machine.  Used only while creating kerberos volume.
          type: str
          version_added: 21.3.0
        server_root_ca_certificate:
          description:
            - When LDAP over SSL/TLS is enabled, the LDAP client is required to have base64 encoded Active Directory Certificate Service's
              self-signed root CA certificate, this optional parameter is used only for dual protocol with LDAP user-mapping volumes.
          type: str
          version_added: 21.3.0
    state:
        description:
            - State C(present) will check that the NetApp account exists with the requested configuration.
            - State C(absent) will delete the NetApp account.
        default: present
        choices:
            - absent
            - present
        type: str
    debug:
      description: output details about current account if it exists.
      type: bool
      default: false

'''
EXAMPLES = '''

- name: Create NetApp Azure Account
  netapp.azure.azure_rm_netapp_account:
    resource_group: myResourceGroup
    name: testaccount
    location: eastus
    tags: {'abc': 'xyz', 'cba': 'zyx'}

- name: Modify Azure NetApp account (Join AD)
  netapp.azure.azure_rm_netapp_account:
    resource_group: myResourceGroup
    name: testaccount
    location: eastus
    active_directories:
      - site: ln
        dns: 10.10.10.10
        domain: domain.com
        smb_server_name: dummy
        password: xxxxxx
        username: laurentn

- name: Delete NetApp Azure Account
  netapp.azure.azure_rm_netapp_account:
    state: absent
    resource_group: myResourceGroup
    name: testaccount
    location: eastus

- name: Create Azure NetApp account (with AD)
  netapp.azure.azure_rm_netapp_account:
    resource_group: laurentngroupnodash
    name: tests-netapp11
    location: eastus
    tags:
      creator: laurentn
      use: Ansible
    active_directories:
      - site: ln
        dns: 10.10.10.10
        domain: domain.com
        smb_server_name: dummy
        password: xxxxxx
        username: laurentn
'''

RETURN = '''
'''

import traceback

HAS_AZURE_MGMT_NETAPP = False
IMPORT_ERRORS = list()

try:
    from msrestazure.azure_exceptions import CloudError
    from azure.core.exceptions import AzureError, ResourceNotFoundError
except ImportError as exc:
    IMPORT_ERRORS.append(str(exc))

try:
    from azure.mgmt.netapp.models import NetAppAccount, NetAppAccountPatch, ActiveDirectory
    HAS_AZURE_MGMT_NETAPP = True
except ImportError as exc:
    IMPORT_ERRORS.append(str(exc))

from ansible.module_utils.basic import to_native
from ansible_collections.netapp.azure.plugins.module_utils.azure_rm_netapp_common import AzureRMNetAppModuleBase
from ansible_collections.netapp.azure.plugins.module_utils.netapp_module import NetAppModule


class AzureRMNetAppAccount(AzureRMNetAppModuleBase):
    ''' create, modify, delete account, including joining AD domain
    '''
    def __init__(self):

        self.module_arg_spec = dict(
            resource_group=dict(type='str', required=True),
            name=dict(type='str', required=True),
            location=dict(type='str', required=False),
            state=dict(choices=['present', 'absent'], default='present', type='str'),
            active_directories=dict(type='list', elements='dict', options=dict(
                active_directory_id=dict(type='str'),
                dns=dict(type='list', elements='str'),
                domain=dict(type='str'),
                site=dict(type='str'),
                smb_server_name=dict(type='str'),
                organizational_unit=dict(type='str'),
                username=dict(type='str'),
                password=dict(type='str', no_log=True),
                aes_encryption=dict(type='bool'),
                ldap_signing=dict(type='bool'),
                ad_name=dict(type='str'),
                kdc_ip=dict(type='str'),
                server_root_ca_certificate=dict(type='str', no_log=True),
            )),
            debug=dict(type='bool', default=False)
        )

        self.na_helper = NetAppModule()
        self.parameters = dict()
        self.debug = list()
        self.warnings = list()

        # import errors are handled in AzureRMModuleBase
        super(AzureRMNetAppAccount, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                   required_if=[('state', 'present', ['location'])],
                                                   supports_check_mode=True)

    def get_azure_netapp_account(self):
        """
            Returns NetApp Account object for an existing account
            Return None if account does not exist
        """
        try:
            account_get = self.netapp_client.accounts.get(self.parameters['resource_group'], self.parameters['name'])
        except (CloudError, ResourceNotFoundError):  # account does not exist
            return None
        account = vars(account_get)
        ads = None
        if account.get('active_directories') is not None:
            ads = list()
            for each_ad in account.get('active_directories'):
                ad_dict = vars(each_ad)
                dns = ad_dict.get('dns')
                if dns is not None:
                    ad_dict['dns'] = sorted(dns.split(','))
                ads.append(ad_dict)
        account['active_directories'] = ads
        return account

    def create_account_request_body(self, modify=None):
        """
            Create an Azure NetApp Account Request Body
            :return: None
        """
        options = dict()
        location = None
        for attr in ('location', 'tags', 'active_directories'):
            value = self.parameters.get(attr)
            if attr == 'location' and modify is None:
                location = value
                continue
            if value is not None:
                if modify is None or attr in modify:
                    if attr == 'active_directories':
                        ads = list()
                        for ad_dict in value:
                            if ad_dict.get('dns') is not None:
                                # API expects a string of comma separated elements
                                ad_dict['dns'] = ','.join(ad_dict['dns'])
                            ads.append(ActiveDirectory(**self.na_helper.filter_out_none_entries(ad_dict)))
                        value = ads
                    options[attr] = value
        if modify is None:
            if location is None:
                self.module.fail_json(msg="Error: 'location' is a required parameter")
            return NetAppAccount(location=location, **options)
        return NetAppAccountPatch(**options)

    def create_azure_netapp_account(self):
        """
            Create an Azure NetApp Account
            :return: None
        """
        account_body = self.create_account_request_body()
        try:
            response = self.get_method('accounts', 'create_or_update')(body=account_body,
                                                                       resource_group_name=self.parameters['resource_group'],
                                                                       account_name=self.parameters['name'])
            while response.done() is not True:
                response.result(10)
        except (CloudError, AzureError) as error:
            self.module.fail_json(msg='Error creating Azure NetApp account %s: %s'
                                  % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def update_azure_netapp_account(self, modify):
        """
            Create an Azure NetApp Account
            :return: None
        """
        account_body = self.create_account_request_body(modify)
        try:
            response = self.get_method('accounts', 'update')(body=account_body,
                                                             resource_group_name=self.parameters['resource_group'],
                                                             account_name=self.parameters['name'])
            while response.done() is not True:
                response.result(10)
        except (CloudError, AzureError) as error:
            self.module.fail_json(msg='Error creating Azure NetApp account %s: %s'
                                  % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def delete_azure_netapp_account(self):
        """
            Delete an Azure NetApp Account
            :return: None
        """
        try:
            response = self.get_method('accounts', 'delete')(resource_group_name=self.parameters['resource_group'],
                                                             account_name=self.parameters['name'])
            while response.done() is not True:
                response.result(10)
        except (CloudError, AzureError) as error:
            self.module.fail_json(msg='Error deleting Azure NetApp account %s: %s'
                                  % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def get_changes_in_ads(self, current, desired):
        c_ads = current.get('active_directories')
        d_ads = desired.get('active_directories')
        if not c_ads:
            return desired.get('active_directories'), None
        if not d_ads:
            return None, current.get('active_directories')
        if len(c_ads) > 1 or len(d_ads) > 1:
            msg = 'Error checking for AD, currently only one AD is supported.'
            if len(c_ads) > 1:
                msg += '  Current: %s.' % str(c_ads)
            if len(d_ads) > 1:
                msg += '  Desired: %s.' % str(d_ads)
            self.module.fail_json(msg='Error checking for AD, currently only one AD is supported')
        changed = False
        d_ad = d_ads[0]
        c_ad = c_ads[0]
        for key, value in c_ad.items():
            if key == 'password':
                if d_ad.get(key) is None:
                    continue
                self.warnings.append("module is not idempotent if 'password:' is present")
            if d_ad.get(key) is None:
                d_ad[key] = value
            elif d_ad.get(key) != value:
                changed = True
                self.debug.append("key: %s, value %s" % (key, value))
        if changed:
            return [d_ad], None
        return None, None

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

        current = self.get_azure_netapp_account()
        modify = None
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        self.debug.append('current: %s' % str(current))
        if current is not None and cd_action is None:
            ads_to_add, ads_to_delete = self.get_changes_in_ads(current, self.parameters)
            self.parameters.pop('active_directories', None)
            if ads_to_add:
                self.parameters['active_directories'] = ads_to_add
            if ads_to_delete:
                self.module.fail_json(msg="Error: API does not support unjoining an AD", debug=self.debug)
            modify = self.na_helper.get_modified_attributes(current, self.parameters)
            if 'tags' in modify:
                dummy, modify['tags'] = self.update_tags(current.get('tags'))

        if self.na_helper.changed:
            if self.module.check_mode:
                pass
            else:
                if cd_action == 'create':
                    self.create_azure_netapp_account()
                elif cd_action == 'delete':
                    self.delete_azure_netapp_account()
                elif modify:
                    self.update_azure_netapp_account(modify)
        results = dict(
            changed=self.na_helper.changed,
            modify=modify
        )
        if self.warnings:
            results['warnings'] = self.warnings
        if self.parameters['debug']:
            results['debug'] = self.debug
        self.module.exit_json(**results)


def main():
    AzureRMNetAppAccount()


if __name__ == '__main__':
    main()

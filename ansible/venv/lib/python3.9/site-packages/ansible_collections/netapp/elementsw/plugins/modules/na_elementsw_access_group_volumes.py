#!/usr/bin/python

# (c) 2019, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Element Software Access Group Volumes
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}


DOCUMENTATION = '''

module: na_elementsw_access_group_volumes

short_description: NetApp Element Software Add/Remove Volumes to/from Access Group
extends_documentation_fragment:
    - netapp.elementsw.netapp.solidfire
version_added: 20.1.0
author: NetApp Ansible Team (@carchi8py) <ng-ansibleteam@netapp.com>
description:
- Add or remove volumes to/from access group on Element Software Cluster.

options:

    state:
        description:
        - Whether the specified volumes should exist or not for this access group.
        choices: ['present', 'absent']
        default: present
        type: str

    access_group:
        description:
        - Name or id for the access group to add volumes to, or remove volumes from
        required: true
        type: str

    volumes:
        description:
        - List of volumes to add/remove from/to the access group.
        - It accepts either volume_name or volume_id
        required: True
        type: list
        elements: str

    account_id:
        description:
        - Account ID for the owner of this volume.
        - It accepts either account_name or account_id
        - if account_id is numeric, look up for account_id first, then look up for account_name
        - If account_id is not numeric, look up for account_name
        required: true
        type: str
'''

EXAMPLES = """
   - name:  Add Volumes to Access Group
     na_elementsw_access_group:
       hostname: "{{ elementsw_hostname }}"
       username: "{{ elementsw_username }}"
       password: "{{ elementsw_password }}"
       state: present
       access_group: AnsibleAccessGroup
       volumes: ['vol7','vol8','vol9']
       account_id: '1'

   - name:  Remove Volumes from Access Group
     na_elementsw_access_group:
       hostname: "{{ elementsw_hostname }}"
       username: "{{ elementsw_username }}"
       password: "{{ elementsw_password }}"
       state: absent
       access_group: AnsibleAccessGroup
       volumes: ['vol7','vol9']
       account_id: '1'
"""


RETURN = """

msg:
    description: Success message
    returned: success
    type: str

"""
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.elementsw.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.elementsw.plugins.module_utils.netapp_elementsw_module import NaElementSWModule

HAS_SF_SDK = netapp_utils.has_sf_sdk()
try:
    import solidfire.common
except ImportError:
    HAS_SF_SDK = False


class ElementSWAccessGroupVolumes(object):
    """
    Element Software Access Group Volumes
    """

    def __init__(self):

        self.argument_spec = netapp_utils.ontap_sf_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            access_group=dict(required=True, type='str'),
            volumes=dict(required=True, type='list', elements='str'),
            account_id=dict(required=True, type='str'),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        input_params = self.module.params

        # Set up state variables
        self.state = input_params['state']
        self.access_group_name = input_params['access_group']
        self.volumes = input_params['volumes']
        self.account_id = input_params['account_id']

        if HAS_SF_SDK is False:
            self.module.fail_json(msg="Unable to import the SolidFire Python SDK")
        else:
            self.sfe = netapp_utils.create_sf_connection(module=self.module)

        self.elementsw_helper = NaElementSWModule(self.sfe)

        # add telemetry attributes
        self.attributes = self.elementsw_helper.set_element_attributes(source='na_elementsw_access_group')

    def get_access_group(self, name):
        """
        Get Access Group
            :description: Get Access Group object for a given name

            :return: object (Group object)
            :rtype: object (Group object)
        """
        access_groups_list = self.sfe.list_volume_access_groups()
        group_obj = None

        for group in access_groups_list.volume_access_groups:
            # Check  and get access_group object for a given name
            if str(group.volume_access_group_id) == name:
                group_obj = group
            elif group.name == name:
                group_obj = group

        return group_obj

    def get_account_id(self):
        # Validate account id
        # Return account_id if found, None otherwise
        try:
            account_id = self.elementsw_helper.account_exists(self.account_id)
            return account_id
        except solidfire.common.ApiServerError:
            return None

    def get_volume_ids(self):
        # Validate volume_ids
        # Return volume ids if found, fail if not found
        volume_ids = []
        for volume in self.volumes:
            volume_id = self.elementsw_helper.volume_exists(volume, self.account_id)
            if volume_id:
                volume_ids.append(volume_id)
            else:
                self.module.fail_json(msg='Error: Specified volume %s does not exist' % volume)
        return volume_ids

    def update_access_group(self, volumes):
        """
        Update the Access Group if the access_group already exists
        """
        try:
            self.sfe.modify_volume_access_group(volume_access_group_id=self.group_id,
                                                volumes=volumes)
        except Exception as e:
            self.module.fail_json(msg="Error updating volume access group %s: %s" %
                                  (self.access_group_name, to_native(e)), exception=traceback.format_exc())

    def apply(self):
        """
        Process the volume add/remove operations for the access group on the Element Software Cluster
        """
        changed = False
        input_account_id = self.account_id

        if self.account_id is not None:
            self.account_id = self.get_account_id()
        if self.account_id is None:
            self.module.fail_json(msg='Error: Specified account id "%s" does not exist.' % str(input_account_id))

        # get volume data
        self.volume_ids = self.get_volume_ids()
        group_detail = self.get_access_group(self.access_group_name)
        if group_detail is None:
            self.module.fail_json(msg='Error: Specified access group "%s" does not exist for account id: %s.' % (self.access_group_name, str(input_account_id)))
        self.group_id = group_detail.volume_access_group_id
        volumes = group_detail.volumes

        # compare expected list of volumes to existing one
        if self.state == "absent":
            # remove volumes if present in access group
            volumes = [vol for vol in group_detail.volumes if vol not in self.volume_ids]
        else:
            # add volumes if not already present
            volumes = [vol for vol in self.volume_ids if vol not in group_detail.volumes]
            volumes.extend(group_detail.volumes)

        # update if there is a change
        if len(volumes) != len(group_detail.volumes):
            if not self.module.check_mode:
                self.update_access_group(volumes)
            changed = True

        self.module.exit_json(changed=changed)


def main():
    """
    Main function
    """
    na_elementsw_access_group_volumes = ElementSWAccessGroupVolumes()
    na_elementsw_access_group_volumes.apply()


if __name__ == '__main__':
    main()

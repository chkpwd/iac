#!/usr/bin/python
# (c) 2018, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

'''
Element Software manage initiators
'''
from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''

module: na_elementsw_initiators

short_description: Manage Element SW initiators
extends_documentation_fragment:
    - netapp.elementsw.netapp.solidfire
version_added: 2.8.0
author: NetApp Ansible Team (@carchi8py) <ng-ansibleteam@netapp.com>
description:
- Manage Element Software initiators that allow external clients access to volumes.

options:
    initiators:
        description: A list of objects containing characteristics of each initiator.
        suboptions:
            name:
                description: The name of the initiator.
                type: str
                required: true

            alias:
                description: The friendly name assigned to this initiator.
                type: str

            initiator_id:
                description: The numeric ID of the initiator.
                type: int

            volume_access_group_id:
                description: volumeAccessGroupID to which this initiator belongs.
                type: int

            attributes:
                description: A set of JSON attributes to assign to this initiator.
                type: dict
        type: list
        elements: dict

    state:
        description:
        - Whether the specified initiator should exist or not.
        choices: ['present', 'absent']
        default: present
        type: str
'''

EXAMPLES = """

  - name: Manage initiators
    tags:
    - na_elementsw_initiators
    na_elementsw_initiators:
      hostname: "{{ elementsw_hostname }}"
      username: "{{ elementsw_username }}"
      password: "{{ elementsw_password }}"
      initiators:
      - name: a
        alias: a1
        initiator_id: 1
        volume_access_group_id: 1
        attributes: {"key": "value"}
      - name: b
        alias: b2
        initiator_id: 2
        volume_access_group_id: 2
    state: present
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
from ansible_collections.netapp.elementsw.plugins.module_utils.netapp_module import NetAppModule
HAS_SF_SDK = netapp_utils.has_sf_sdk()
if HAS_SF_SDK:
    from solidfire.models import ModifyInitiator


class ElementSWInitiators(object):
    """
    Element Software Manage Element SW initiators
    """
    def __init__(self):
        self.argument_spec = netapp_utils.ontap_sf_host_argument_spec()

        self.argument_spec.update(dict(
            initiators=dict(
                type='list',
                elements='dict',
                options=dict(
                    name=dict(type='str', required=True),
                    alias=dict(type='str', default=None),
                    initiator_id=dict(type='int', default=None),
                    volume_access_group_id=dict(type='int', default=None),
                    attributes=dict(type='dict', default=None),
                )
            ),
            state=dict(choices=['present', 'absent'], default='present'),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.debug = list()

        if HAS_SF_SDK is False:
            self.module.fail_json(msg="Unable to import the SolidFire Python SDK")
        else:
            self.sfe = netapp_utils.create_sf_connection(module=self.module)

        self.elementsw_helper = NaElementSWModule(self.sfe)

        # iterate over each user-provided initiator
        for initiator in self.parameters.get('initiators'):
            # add telemetry attributes
            if 'attributes' in initiator and initiator['attributes']:
                initiator['attributes'].update(self.elementsw_helper.set_element_attributes(source='na_elementsw_initiators'))
            else:
                initiator['attributes'] = self.elementsw_helper.set_element_attributes(source='na_elementsw_initiators')

    def compare_initiators(self, user_initiator, existing_initiator):
        """
        compare user input initiator with existing dict
        :return: True if matched, False otherwise
        """
        if user_initiator is None or existing_initiator is None:
            return False
        changed = False
        for param in user_initiator:
            # lookup initiator_name instead of name
            if param == 'name':
                if user_initiator['name'] == existing_initiator['initiator_name']:
                    pass
            elif param == 'initiator_id':
                # can't change the key
                pass
            elif user_initiator[param] == existing_initiator[param]:
                pass
            else:
                self.debug.append('Initiator: %s.  Changed: %s from: %s to %s' %
                                  (user_initiator['name'], param, str(existing_initiator[param]), str(user_initiator[param])))
                changed = True
        return changed

    def initiator_to_dict(self, initiator_obj):
        """
        converts initiator class object to dict
        :return: reconstructed initiator dict
        """
        known_params = ['initiator_name',
                        'alias',
                        'initiator_id',
                        'volume_access_groups',
                        'volume_access_group_id',
                        'attributes']
        initiator_dict = {}

        # missing parameter cause error
        # so assign defaults
        for param in known_params:
            initiator_dict[param] = getattr(initiator_obj, param, None)
        if initiator_dict['volume_access_groups'] is not None:
            if len(initiator_dict['volume_access_groups']) == 1:
                initiator_dict['volume_access_group_id'] = initiator_dict['volume_access_groups'][0]
            elif len(initiator_dict['volume_access_groups']) > 1:
                self.module.fail_json(msg="Only 1 access group is supported, found: %s" % repr(initiator_obj))
        del initiator_dict['volume_access_groups']
        return initiator_dict

    def find_initiator(self, id=None, name=None):
        """
        find a specific initiator
        :return: initiator dict
        """
        initiator_details = None
        if self.all_existing_initiators is None:
            return initiator_details
        for initiator in self.all_existing_initiators:
            # if name is provided or
            # if id is provided
            if name is not None:
                if initiator.initiator_name == name:
                    initiator_details = self.initiator_to_dict(initiator)
            elif id is not None:
                if initiator.initiator_id == id:
                    initiator_details = self.initiator_to_dict(initiator)
            else:
                # if neither id nor name provided
                # return everything
                initiator_details = self.all_existing_initiators
        return initiator_details

    @staticmethod
    def rename_key(obj, old_name, new_name):
        obj[new_name] = obj.pop(old_name)

    def create_initiator(self, initiator):
        """
        create initiator
        """
        # SF SDK is using camelCase for this one
        self.rename_key(initiator, 'volume_access_group_id', 'volumeAccessGroupID')
        # create_initiators needs an array
        initiator_list = [initiator]
        try:
            self.sfe.create_initiators(initiator_list)
        except Exception as exception_object:
            self.module.fail_json(msg='Error creating initiator %s' % (to_native(exception_object)),
                                  exception=traceback.format_exc())

    def delete_initiator(self, initiator):
        """
        delete initiator
        """
        # delete_initiators needs an array
        initiator_id_array = [initiator]
        try:
            self.sfe.delete_initiators(initiator_id_array)
        except Exception as exception_object:
            self.module.fail_json(msg='Error deleting initiator %s' % (to_native(exception_object)),
                                  exception=traceback.format_exc())

    def modify_initiator(self, initiator, existing_initiator):
        """
        modify initiator
        """
        # create the new initiator dict
        # by merging old and new values
        merged_initiator = existing_initiator.copy()
        # can't change the key
        del initiator['initiator_id']
        merged_initiator.update(initiator)

        # we MUST create an object before sending
        # the new initiator to modify_initiator
        initiator_object = ModifyInitiator(initiator_id=merged_initiator['initiator_id'],
                                           alias=merged_initiator['alias'],
                                           volume_access_group_id=merged_initiator['volume_access_group_id'],
                                           attributes=merged_initiator['attributes'])
        initiator_list = [initiator_object]
        try:
            self.sfe.modify_initiators(initiators=initiator_list)
        except Exception as exception_object:
            self.module.fail_json(msg='Error modifying initiator: %s' % (to_native(exception_object)),
                                  exception=traceback.format_exc())

    def apply(self):
        """
        configure initiators
        """
        changed = False
        result_message = None

        # get all user provided initiators
        input_initiators = self.parameters.get('initiators')

        # get all initiators
        # store in a cache variable
        self.all_existing_initiators = self.sfe.list_initiators().initiators

        # iterate over each user-provided initiator
        for in_initiator in input_initiators:
            if self.parameters.get('state') == 'present':
                # check if initiator_id is provided and exists
                if 'initiator_id' in in_initiator and in_initiator['initiator_id'] is not None and \
                        self.find_initiator(id=in_initiator['initiator_id']) is not None:
                    if self.compare_initiators(in_initiator, self.find_initiator(id=in_initiator['initiator_id'])):
                        changed = True
                        result_message = 'modifying initiator(s)'
                        self.modify_initiator(in_initiator, self.find_initiator(id=in_initiator['initiator_id']))
                # otherwise check if name is provided and exists
                elif 'name' in in_initiator and in_initiator['name'] is not None and self.find_initiator(name=in_initiator['name']) is not None:
                    if self.compare_initiators(in_initiator, self.find_initiator(name=in_initiator['name'])):
                        changed = True
                        result_message = 'modifying initiator(s)'
                        self.modify_initiator(in_initiator, self.find_initiator(name=in_initiator['name']))
                # this is a create op if initiator doesn't exist
                else:
                    changed = True
                    result_message = 'creating initiator(s)'
                    self.create_initiator(in_initiator)
            elif self.parameters.get('state') == 'absent':
                # delete_initiators only processes ids
                # so pass ids of initiators to method
                if 'name' in in_initiator and in_initiator['name'] is not None and \
                        self.find_initiator(name=in_initiator['name']) is not None:
                    changed = True
                    result_message = 'deleting initiator(s)'
                    self.delete_initiator(self.find_initiator(name=in_initiator['name'])['initiator_id'])
                elif 'initiator_id' in in_initiator and in_initiator['initiator_id'] is not None and \
                        self.find_initiator(id=in_initiator['initiator_id']) is not None:
                    changed = True
                    result_message = 'deleting initiator(s)'
                    self.delete_initiator(in_initiator['initiator_id'])
        if self.module.check_mode is True:
            result_message = "Check mode, skipping changes"
        if self.debug:
            result_message += ".  %s" % self.debug
        self.module.exit_json(changed=changed, msg=result_message)


def main():
    """
    Main function
    """
    na_elementsw_initiators = ElementSWInitiators()
    na_elementsw_initiators.apply()


if __name__ == '__main__':
    main()

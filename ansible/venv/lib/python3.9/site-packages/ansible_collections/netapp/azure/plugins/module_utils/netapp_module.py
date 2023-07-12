# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# Copyright (c) 2018, Laurent Nicolas <laurentn@netapp.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

''' Support class for NetApp ansible modules '''

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.module_utils import basic


class AzureRMModuleBaseMock():
    ''' Mock for sanity tests when azcollection is not installed '''
    def __init__(self, derived_arg_spec, required_if=None, supports_check_mode=False, supports_tags=True, **kwargs):
        if supports_tags:
            derived_arg_spec.update(dict(tags=dict()))
        self.module = basic.AnsibleModule(
            argument_spec=derived_arg_spec,
            required_if=required_if,
            supports_check_mode=supports_check_mode
        )
        self.module.warn('Running in Unit Test context!')
        # the following is done in exec_module()
        self.parameters = dict([item for item in self.module.params.items() if item[1] is not None])
        # remove values with a default of None (not required)
        self.module_arg_spec = dict([item for item in self.module_arg_spec.items() if item[0] in self.parameters])

    def update_tags(self, tags):
        self.module.log('update_tags called with:', tags)
        return None, None


def cmp(obj1, obj2):
    """
    Python 3 does not have a cmp function, this will do the cmp.
    :param a: first object to check
    :param b: second object to check
    :return:
    """
    # convert to lower case for string comparison.
    if obj1 is None:
        return -1
    if isinstance(obj1, str) and isinstance(obj2, str):
        obj1 = obj1.lower()
        obj2 = obj2.lower()
    # if list has string element, convert string to lower case.
    if isinstance(obj1, list) and isinstance(obj2, list):
        obj1 = [x.lower() if isinstance(x, str) else x for x in obj1]
        obj2 = [x.lower() if isinstance(x, str) else x for x in obj2]
        obj1.sort()
        obj2.sort()
    if isinstance(obj1, dict) and isinstance(obj2, dict):
        return 0 if obj1 == obj2 else 1
    return (obj1 > obj2) - (obj1 < obj2)


class NetAppModule():
    '''
    Common class for NetApp modules
    set of support functions to derive actions based
    on the current state of the system, and a desired state
    '''

    def __init__(self):
        self.log = []
        self.changed = False
        self.parameters = {'name': 'not intialized'}
        self.zapi_string_keys = dict()
        self.zapi_bool_keys = dict()
        self.zapi_list_keys = {}
        self.zapi_int_keys = {}
        self.zapi_required = {}

    def set_parameters(self, ansible_params):
        self.parameters = {}
        for param in ansible_params:
            if ansible_params[param] is not None:
                self.parameters[param] = ansible_params[param]
        return self.parameters

    def get_cd_action(self, current, desired):
        ''' takes a desired state and a current state, and return an action:
            create, delete, None
            eg:
            is_present = 'absent'
            some_object = self.get_object(source)
            if some_object is not None:
                is_present = 'present'
            action = cd_action(current=is_present, desired = self.desired.state())
        '''
        desired_state = desired['state'] if 'state' in desired else 'present'
        if current is None and desired_state == 'absent':
            return None
        if current is not None and desired_state == 'present':
            return None
        # change in state
        self.changed = True
        if current is not None:
            return 'delete'
        return 'create'

    def compare_and_update_values(self, current, desired, keys_to_compare):
        updated_values = {}
        is_changed = False
        for key in keys_to_compare:
            if key in current:
                if key in desired and desired[key] is not None:
                    if current[key] != desired[key]:
                        updated_values[key] = desired[key]
                        is_changed = True
                    else:
                        updated_values[key] = current[key]
                else:
                    updated_values[key] = current[key]

        return updated_values, is_changed

    @staticmethod
    def check_keys(current, desired):
        ''' TODO: raise an error if keys do not match
            with the exception of:
            new_name, state in desired
        '''

    @staticmethod
    def compare_lists(current, desired, get_list_diff):
        ''' compares two lists and return a list of elements that are either the desired elements or elements that are
            modified from the current state depending on the get_list_diff flag
            :param: current: current item attribute in ONTAP
            :param: desired: attributes from playbook
            :param: get_list_diff: specifies whether to have a diff of desired list w.r.t current list for an attribute
            :return: list of attributes to be modified
            :rtype: list
        '''
        desired_diff_list = [item for item in desired if item not in current]  # get what in desired and not in current
        current_diff_list = [item for item in current if item not in desired]  # get what in current but not in desired

        if desired_diff_list or current_diff_list:
            # there are changes
            if get_list_diff:
                return desired_diff_list
            else:
                return desired
        else:
            return []

    def get_modified_attributes(self, current, desired, get_list_diff=False):
        ''' takes two dicts of attributes and return a dict of attributes that are
            not in the current state
            It is expected that all attributes of interest are listed in current and
            desired.
            :param: current: current attributes in ONTAP
            :param: desired: attributes from playbook
            :param: get_list_diff: specifies whether to have a diff of desired list w.r.t current list for an attribute
            :return: dict of attributes to be modified
            :rtype: dict

            NOTE: depending on the attribute, the caller may need to do a modify or a
            different operation (eg move volume if the modified attribute is an
            aggregate name)
        '''
        # if the object does not exist,  we can't modify it
        modified = {}
        if current is None:
            return modified

        # error out if keys do not match
        self.check_keys(current, desired)

        # collect changed attributes
        for key, value in current.items():
            if key in desired and desired[key] is not None:
                if isinstance(value, list):
                    modified_list = self.compare_lists(value, desired[key], get_list_diff)  # get modified list from current and desired
                    if modified_list:
                        modified[key] = modified_list
                elif cmp(value, desired[key]) != 0:
                    modified[key] = desired[key]
        if modified:
            self.changed = True
        return modified

    def is_rename_action(self, source, target):
        ''' takes a source and target object, and returns True
            if a rename is required
            eg:
            source = self.get_object(source_name)
            target = self.get_object(target_name)
            action = is_rename_action(source, target)
            :return: None for error, True for rename action, False otherwise
        '''
        if source is None and target is None:
            # error, do nothing
            # cannot rename an non existent resource
            # alternatively we could create B
            return None
        if source is not None and target is not None:
            # error, do nothing
            # idempotency (or) new_name_is_already_in_use
            # alternatively we could delete B and rename A to B
            return False
        if source is None:
            # do nothing, maybe the rename was already done
            return False
        # source is not None and target is None:
        # rename is in order
        self.changed = True
        return True

    def filter_out_none_entries(self, list_or_dict):
        """take a dict or list as input and return a dict/list without keys/elements whose values are None
           skip empty dicts or lists.
        """

        if isinstance(list_or_dict, dict):
            result = {}
            for key, value in list_or_dict.items():
                if isinstance(value, (list, dict)):
                    sub = self.filter_out_none_entries(value)
                    if sub:
                        # skip empty dict or list
                        result[key] = sub
                elif value is not None:
                    # skip None value
                    result[key] = value
            return result

        if isinstance(list_or_dict, list):
            alist = []
            for item in list_or_dict:
                if isinstance(item, (list, dict)):
                    sub = self.filter_out_none_entries(item)
                    if sub:
                        # skip empty dict or list
                        alist.append(sub)
                elif item is not None:
                    # skip None value
                    alist.append(item)
            return alist

        raise TypeError('unexpected type %s' % type(list_or_dict))

    @staticmethod
    def get_not_none_values_from_dict(parameters, keys):
        # python 2.6 does not support dict comprehension using k: v
        return dict((key, value) for key, value in parameters.items() if key in keys and value is not None)

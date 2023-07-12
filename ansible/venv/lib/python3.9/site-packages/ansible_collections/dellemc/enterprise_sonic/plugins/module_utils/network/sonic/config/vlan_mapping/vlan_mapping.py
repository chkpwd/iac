#
# -*- coding: utf-8 -*-
# Copyright 2023 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_vlan_mapping class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.cfg.base import (
    ConfigBase,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    to_list,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    get_diff,
    update_states,
    remove_empties_from_list,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible.module_utils.connection import ConnectionError


TEST_KEYS = [
    {'config': {'name': ''}},
    {'mapping': {'service_vlan': '', 'dot1q_tunnel': ''}},
]


class Vlan_mapping(ConfigBase):
    """
    The sonic_vlan_mapping class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'vlan_mapping',
    ]

    def __init__(self, module):
        super(Vlan_mapping, self).__init__(module)

    def get_vlan_mapping_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        vlan_mapping_facts = facts['ansible_network_resources'].get('vlan_mapping')
        if not vlan_mapping_facts:
            return []
        return vlan_mapping_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()

        existing_vlan_mapping_facts = self.get_vlan_mapping_facts()
        commands, requests = self.set_config(existing_vlan_mapping_facts)
        if commands:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_vlan_mapping_facts = self.get_vlan_mapping_facts()

        result['before'] = existing_vlan_mapping_facts
        if result['changed']:
            result['after'] = changed_vlan_mapping_facts

        result['warnings'] = warnings
        return result

    def set_config(self, existing_vlan_mapping_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = remove_empties_from_list(self._module.params['config'])
        have = existing_vlan_mapping_facts
        resp = self.set_state(want, have)
        return to_list(resp)

    def set_state(self, want, have):
        """ Select the appropriate function based on the state provided

        :param want: the desired configuration as a dictionary
        :param have: the current configuration as a dictionary
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        state = self._module.params['state']
        have = self.convert_vlan_ids_range(have)
        want = self.convert_vlan_ids_range(want)
        diff = get_diff(want, have, TEST_KEYS)

        if state == 'overridden':
            commands, requests = self._state_overridden(want, have, diff)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        elif state == 'merged':
            commands, requests = self._state_merged(want, have, diff)
        elif state == 'replaced':
            commands, requests = self._state_replaced(want, have, diff)

        ret_commands = remove_empties_from_list(commands)
        return ret_commands, requests

    def _state_replaced(self, want, have, diff):
        """ The command generator when state is replaced

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        requests = []
        commands = []
        commands_del = []

        commands_del = self.get_replaced_delete_list(want, have)

        if commands_del:
            commands.extend(update_states(commands_del, "deleted"))

            requests_del = self.get_delete_vlan_mapping_requests(commands_del, have, is_delete_all=True)
            if requests_del:
                requests.extend(requests_del)

        if diff or commands_del:
            requests_rep = self.get_create_vlan_mapping_requests(want, have)
            if len(requests_rep):
                requests.extend(requests_rep)
                commands = update_states(want, "replaced")
            else:
                commands = []

        return commands, requests

    def _state_overridden(self, want, have, diff):
        """ The command generator when state is overridden

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        requests = []

        commands_del = get_diff(have, want, TEST_KEYS)
        if commands_del:
            requests_del = self.get_delete_vlan_mapping_requests(commands_del, have, is_delete_all=True)
            requests.extend(requests_del)
            commands_del = update_states(commands_del, "deleted")
            commands.extend(commands_del)

        commands_over = diff
        if diff:
            requests_over = self.get_create_vlan_mapping_requests(commands_over, have)
            requests.extend(requests_over)
            commands_over = update_states(commands_over, "overridden")
            commands.extend(commands_over)

        return commands, requests

    def _state_merged(self, want, have, diff):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = diff
        requests = self.get_create_vlan_mapping_requests(commands, have)

        if commands and len(requests):
            commands = update_states(commands, 'merged')
        else:
            commands = []

        return commands, requests

    def _state_deleted(self, want, have):
        """ The command generator when state is deleted

        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        commands = []
        requests = []
        is_delete_all = False

        if not want:
            commands = have
            is_delete_all = True
        else:
            commands = want

        requests.extend(self.get_delete_vlan_mapping_requests(commands, have, is_delete_all))

        if len(requests) == 0:
            commands = []

        if commands:
            commands = update_states(commands, 'deleted')

        return commands, requests

    def get_replaced_delete_list(self, commands, have):
        matched = []

        for cmd in commands:
            name = cmd.get('name', None)
            interface_name = name.replace('/', '%2f')
            mapping_list = cmd.get('mapping', [])

            matched_interface_name = None
            matched_mapping_list = []
            for existing in have:
                have_name = existing.get('name', None)
                have_interface_name = have_name.replace('/', '%2f')
                have_mapping_list = existing.get('mapping', [])
                if interface_name == have_interface_name:
                    matched_interface_name = have_interface_name
                    matched_mapping_list = have_mapping_list

            if mapping_list and matched_mapping_list:
                returned_mapping_list = []
                for mapping in mapping_list:
                    service_vlan = mapping.get('service_vlan', None)

                    for matched_mapping in matched_mapping_list:
                        matched_service_vlan = matched_mapping.get('service_vlan', None)

                        if matched_service_vlan and service_vlan:
                            if matched_service_vlan == service_vlan:
                                priority = mapping.get('priority', None)
                                have_priority = matched_mapping.get('priority', None)
                                inner_vlan = mapping.get('inner_vlan', None)
                                have_inner_vlan = matched_mapping.get('inner_vlan', None)
                                dot1q_tunnel = mapping.get('dot1q_tunnel', False)
                                have_dot1q_tunnel = matched_mapping.get('dot1q_tunnel', False)
                                vlan_ids = mapping.get('vlan_ids', [])
                                have_vlan_ids = matched_mapping.get('vlan_ids', [])

                                if priority != have_priority:
                                    returned_mapping_list.append(mapping)
                                elif inner_vlan != have_inner_vlan:
                                    returned_mapping_list.append(mapping)
                                elif dot1q_tunnel != have_dot1q_tunnel:
                                    returned_mapping_list.append(mapping)
                                elif sorted(vlan_ids) != sorted(have_vlan_ids):
                                    returned_mapping_list.append(mapping)

                if returned_mapping_list:
                    matched.append({'name': interface_name, 'mapping': returned_mapping_list})

        return matched

    def get_delete_vlan_mapping_requests(self, commands, have, is_delete_all):
        """ Get list of requests to delete vlan mapping configurations
        for all interfaces specified by the commands
        """
        url = "data/openconfig-interfaces:interfaces/interface={}/openconfig-interfaces-ext:mapped-vlans/mapped-vlan={}"
        priority_url = "/ingress-mapping/config/mapped-vlan-priority"
        vlan_ids_url = "/match/single-tagged/config/vlan-ids={}"
        method = "DELETE"
        requests = []

        # Delete all vlan mappings
        if is_delete_all:
            for cmd in commands:
                name = cmd.get('name', None)
                interface_name = name.replace('/', '%2f')
                mapping_list = cmd.get('mapping', [])

                if mapping_list:
                    for mapping in mapping_list:
                        service_vlan = mapping.get('service_vlan', None)
                        path = url.format(interface_name, service_vlan)
                        request = {"path": path, "method": method}
                        requests.append(request)

            return requests

        else:
            for cmd in commands:
                name = cmd.get('name', None)
                interface_name = name.replace('/', '%2f')
                mapping_list = cmd.get('mapping', [])

                # Checks if there is a interface matching the delete command
                have_interface_name = None
                have_mapping_list = []
                for tmp in have:
                    tmp_name = tmp.get('name', None)
                    tmp_interface_name = tmp_name.replace('/', '%2f')
                    tmp_mapping_list = tmp.get('mapping', [])
                    if interface_name == tmp_interface_name:
                        have_interface_name = tmp_interface_name
                        have_mapping_list = tmp_mapping_list

                # Delete part or all of single mapping
                if mapping_list:
                    for mapping in mapping_list:
                        service_vlan = mapping.get('service_vlan', None)
                        vlan_ids = mapping.get('vlan_ids', None)
                        priority = mapping.get('priority', None)

                        # Checks if there is a vlan mapping matching the delete command
                        have_service_vlan = None
                        have_vlan_ids = None
                        have_priority = None
                        for have_mapping in have_mapping_list:
                            if have_mapping.get('service_vlan', None) == service_vlan:
                                have_service_vlan = have_mapping.get('service_vlan', None)
                                have_vlan_ids = have_mapping.get('vlan_ids', None)
                                have_priority = have_mapping.get('priority', None)

                        if service_vlan and have_service_vlan:
                            if vlan_ids or priority:
                                # Delete priority
                                if priority and have_priority:
                                    path = url.format(interface_name, service_vlan) + priority_url
                                    request = {"path": path, "method": method}
                                    requests.append(request)
                                # Delete vlan ids
                                if vlan_ids and have_vlan_ids:
                                    vlan_ids_str = ""
                                    same_vlan_ids_list = self.get_vlan_ids_diff(vlan_ids, have_vlan_ids, same=True)
                                    if same_vlan_ids_list:
                                        for vlan in same_vlan_ids_list:
                                            if vlan_ids_str:
                                                vlan_ids_str = vlan_ids_str + "%2C" + vlan.replace("-", "..")
                                            else:
                                                vlan_ids_str = vlan.replace("-", "..")
                                        path = url.format(interface_name, service_vlan) + vlan_ids_url.format(vlan_ids_str)
                                        request = {"path": path, "method": method}
                                        requests.append(request)
                            # Delete entire mapping
                            else:
                                path = url.format(interface_name, service_vlan)
                                request = {"path": path, "method": method}
                                requests.append(request)
                # Delete all mappings in an interface
                else:
                    if have_mapping_list:
                        for mapping in have_mapping_list:
                            service_vlan = mapping.get('service_vlan', None)
                            path = url.format(interface_name, service_vlan)
                            request = {"path": path, "method": method}
                            requests.append(request)

            return requests

    def get_create_vlan_mapping_requests(self, commands, have):
        """ Get list of requests to create/modify vlan mapping configurations
        for all interfaces specified by the commands
        """
        requests = []
        if not commands:
            return requests

        for cmd in commands:
            name = cmd.get('name', None)
            interface_name = name.replace('/', '%2f')
            mapping_list = cmd.get('mapping', [])

            if mapping_list:
                for mapping in mapping_list:
                    requests.append(self.get_create_vlan_mapping_request(interface_name, mapping))
        return requests

    def get_create_vlan_mapping_request(self, interface_name, mapping):
        url = "data/openconfig-interfaces:interfaces/interface={}/openconfig-interfaces-ext:mapped-vlans"
        body = {}
        method = "PATCH"
        match_data = None

        service_vlan = mapping.get('service_vlan', None)
        priority = mapping.get('priority', None)
        vlan_ids = mapping.get('vlan_ids', [])
        dot1q_tunnel = mapping.get('dot1q_tunnel', None)
        inner_vlan = mapping.get('inner_vlan', None)

        if not dot1q_tunnel:
            if len(vlan_ids) > 1:
                raise Exception("When dot1q-tunnel is false only one VLAN ID can be passed to the vlan_ids list")
            if not vlan_ids and priority:
                match_data = None
            elif vlan_ids:
                if inner_vlan:
                    match_data = {'double-tagged': {'config': {'inner-vlan-id': inner_vlan, 'outer-vlan-id': int(vlan_ids[0])}}}
                else:
                    match_data = {'single-tagged': {'config': {'vlan-ids': [int(vlan_ids[0])]}}}
            if priority:
                ing_data = {'config': {'vlan-stack-action': 'SWAP', 'mapped-vlan-priority': priority}}
                egr_data = {'config': {'vlan-stack-action': 'SWAP', 'mapped-vlan-priority': priority}}
            else:
                ing_data = {'config': {'vlan-stack-action': 'SWAP'}}
                egr_data = {'config': {'vlan-stack-action': 'SWAP'}}
        else:
            if inner_vlan:
                raise Exception("Inner vlan can only be passed when dot1q_tunnel is false")
            if not vlan_ids and priority:
                match_data = None
            elif vlan_ids:
                vlan_ids_list = []
                for vlan in vlan_ids:
                    vlan_ids_list.append(int(vlan))
                match_data = {'single-tagged': {'config': {'vlan-ids': vlan_ids_list}}}
            if priority:
                ing_data = {'config': {'vlan-stack-action': 'PUSH', 'mapped-vlan-priority': priority}}
                egr_data = {'config': {'vlan-stack-action': 'POP', 'mapped-vlan-priority': priority}}
            else:
                ing_data = {'config': {'vlan-stack-action': 'PUSH'}}
                egr_data = {'config': {'vlan-stack-action': 'POP'}}
        if match_data:
            body = {'openconfig-interfaces-ext:mapped-vlans': {'mapped-vlan': [
                {'vlan-id': service_vlan,
                 'config': {'vlan-id': service_vlan},
                 'match': match_data,
                 'ingress-mapping': ing_data,
                 'egress-mapping': egr_data}
            ]}}
        else:
            body = {'openconfig-interfaces-ext:mapped-vlans': {'mapped-vlan': [
                {'vlan-id': service_vlan,
                 'config': {'vlan-id': service_vlan},
                 'ingress-mapping': ing_data,
                 'egress-mapping': egr_data}
            ]}}

        request = {"path": url.format(interface_name), "method": method, "data": body}
        return request

    def get_vlan_ids_diff(self, vlan_ids, have_vlan_ids, same):
        """ Takes two vlan id lists and finds the difference.
        :param vlan_ids: list of vlan ids that is looking for diffs
        :param have_vlan_ids: list of vlan ids that is being compared to
        :param same: if true will instead return list of shared values
        :rtype: list(str)
        """
        results = []

        for vlan_id in vlan_ids:
            if same:
                if vlan_id in have_vlan_ids:
                    results.append(vlan_id)
            else:
                if vlan_id not in have_vlan_ids:
                    results.append(vlan_id)

        return results

    def vlanIdsRangeStr(self, vlanList):
        rangeList = []
        for vid in vlanList:
            if "-" in vid:
                vidList = vid.split("-")
                lower = int(vidList[0])
                upper = int(vidList[1])
                for i in range(lower, upper + 1):
                    rangeList.append(str(i))
            else:
                rangeList.append(vid)
        return rangeList

    def convert_vlan_ids_range(self, config):

        interface_index = 0
        for conf in config:
            name = conf.get('name', None)
            interface_name = name.replace('/', '%2f')
            mapping_list = conf.get('mapping', [])

            mapping_index = 0
            if mapping_list:
                for mapping in mapping_list:
                    vlan_ids = mapping.get('vlan_ids', None)

                    if vlan_ids:
                        config[interface_index]['mapping'][mapping_index]['vlan_ids'] = self.vlanIdsRangeStr(vlan_ids)
                    mapping_index = mapping_index + 1
            interface_index = interface_index + 1

        return config

#
# -*- coding: utf-8 -*-
# Copyright 2020 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_bgp_as_paths class
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
    update_states,
    get_diff,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible.module_utils.connection import ConnectionError

try:
    from urllib.parse import urlencode
except Exception:
    from urllib import urlencode


class Bgp_as_paths(ConfigBase):
    """
    The sonic_bgp_as_paths class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'bgp_as_paths',
    ]

    def __init__(self, module):
        super(Bgp_as_paths, self).__init__(module)

    def get_bgp_as_paths_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        bgp_as_paths_facts = facts['ansible_network_resources'].get('bgp_as_paths')
        if not bgp_as_paths_facts:
            return []
        return bgp_as_paths_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()
        commands = list()

        existing_bgp_as_paths_facts = self.get_bgp_as_paths_facts()
        commands, requests = self.set_config(existing_bgp_as_paths_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_bgp_as_paths_facts = self.get_bgp_as_paths_facts()

        result['before'] = existing_bgp_as_paths_facts
        if result['changed']:
            result['after'] = changed_bgp_as_paths_facts

        result['warnings'] = warnings
        return result

    def set_config(self, existing_bgp_as_paths_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        have = existing_bgp_as_paths_facts
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
        commands = []
        requests = []
        state = self._module.params['state']
        diff = get_diff(want, have)
        if state == 'overridden':
            commands, requests = self._state_overridden(want, have, diff)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        elif state == 'merged':
            commands, requests = self._state_merged(want, have, diff)
        elif state == 'replaced':
            commands, requests = self._state_replaced(want, have, diff)
        return commands, requests

    @staticmethod
    def _state_replaced(**kwargs):
        """ The command generator when state is replaced

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        return commands

    @staticmethod
    def _state_overridden(**kwargs):
        """ The command generator when state is overridden

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        return commands

    def _state_merged(self, want, have, diff):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = diff
        for cmd in commands:
            match = next((item for item in have if item['name'] == cmd['name']), None)
            if match:
                # Use existing action if not specified
                if cmd.get('permit') is None:
                    cmd['permit'] = match['permit']
                elif cmd['permit'] != match['permit']:
                    action = 'permit' if match['permit'] else 'deny'
                    self._module.fail_json(msg='Cannot override existing action {0} of {1}'.format(action, cmd['name']))
            # Set action to deny if not specfied for a new as-path-list
            elif cmd.get('permit') is None:
                cmd['permit'] = False

        requests = self.get_modify_as_path_list_requests(commands, have)
        if commands and len(requests) > 0:
            commands = update_states(commands, "merged")
        else:
            commands = []

        return commands, requests

    def _state_deleted(self, want, have):
        """ The command generator when state is deleted

        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        # To Delete a single member
        # data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/as-path-sets/as-path-set=xyz/config/as-path-set-member=11
        # This will delete the as path and its all members
        # data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/as-path-sets/as-path-set=xyz
        # This will delete ALL as path completely
        # data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/as-path-sets

        is_delete_all = False
        # if want is none, then delete ALL
        if not want:
            commands = have
            is_delete_all = True
        else:
            commands = want

        requests = self.get_delete_as_path_requests(commands, have, is_delete_all)

        if commands and len(requests) > 0:
            commands = update_states(commands, "deleted")
        else:
            commands = []

        return commands, requests

    def get_new_add_request(self, conf):
        request = None
        members = conf.get('members', None)
        permit = conf.get('permit', None)
        permit_str = ""
        if permit:
            permit_str = "PERMIT"
        else:
            permit_str = "DENY"
        if members:
            url = "data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/as-path-sets"
            method = "PATCH"
            cfg = {'as-path-set-name': conf['name'], 'as-path-set-member': members, 'openconfig-bgp-policy-ext:action': permit_str}
            as_path_set = {'as-path-set-name': conf['name'], 'config': cfg}
            payload = {'openconfig-bgp-policy:as-path-sets': {'as-path-set': [as_path_set]}}
            request = {"path": url, "method": method, "data": payload}
        return request

    def get_delete_all_as_path_requests(self, commands):
        url = "data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/as-path-sets"
        method = "DELETE"
        requests = []
        if commands:
            request = {"path": url, "method": method}
            requests.append(request)
        return requests

    def get_delete_single_as_path_member_requests(self, name, members):
        url = "data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:"
        url = url + "bgp-defined-sets/as-path-sets/as-path-set={name}/config/{members_param}"
        method = "DELETE"
        members_params = {'as-path-set-member': ','.join(members)}
        members_str = urlencode(members_params)
        request = {"path": url.format(name=name, members_param=members_str), "method": method}
        return request

    def get_delete_single_as_path_requests(self, name):
        url = "data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/as-path-sets/as-path-set={}"
        method = "DELETE"
        request = {"path": url.format(name), "method": method}
        return request

    def get_delete_as_path_requests(self, commands, have, is_delete_all):
        requests = []
        if is_delete_all:
            requests = self.get_delete_all_as_path_requests(commands)
        else:
            for cmd in commands:
                name = cmd['name']
                members = cmd['members']
                permit = cmd['permit']
                match = next((item for item in have if item['name'] == cmd['name']), None)
                if match:
                    if members:
                        if match.get('members'):
                            del_members = set(match['members']).intersection(set(members))
                            if del_members:
                                if len(del_members) == len(match['members']):
                                    requests.append(self.get_delete_single_as_path_requests(name))
                                else:
                                    requests.append(self.get_delete_single_as_path_member_requests(name, del_members))
                    else:
                        requests.append(self.get_delete_single_as_path_requests(name))

        return requests

    def get_modify_as_path_list_requests(self, commands, have):
        requests = []
        if not commands:
            return requests

        for conf in commands:
            new_req = self.get_new_add_request(conf)
            if new_req:
                requests.append(new_req)
        return requests

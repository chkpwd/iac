#
# -*- coding: utf-8 -*-
# Copyright 2020 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_bgp_communities class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import to_request
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible.module_utils.connection import ConnectionError
import json
from ansible.module_utils._text import to_native
import traceback
try:
    import jinja2
    HAS_LIB = True
except Exception as e:
    HAS_LIB = False
    ERR_MSG = to_native(e)
    LIB_IMP_ERR = traceback.format_exc()

try:
    from urllib.parse import urlencode
except Exception:
    from urllib import urlencode


class Bgp_communities(ConfigBase):
    """
    The sonic_bgp_communities class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'bgp_communities',
    ]

    def __init__(self, module):
        super(Bgp_communities, self).__init__(module)

    def get_bgp_communities_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        bgp_communities_facts = facts['ansible_network_resources'].get('bgp_communities')
        if not bgp_communities_facts:
            return []
        return bgp_communities_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()
        commands = list()

        existing_bgp_communities_facts = self.get_bgp_communities_facts()
        commands, requests = self.set_config(existing_bgp_communities_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_bgp_communities_facts = self.get_bgp_communities_facts()

        result['before'] = existing_bgp_communities_facts
        if result['changed']:
            result['after'] = changed_bgp_communities_facts

        result['warnings'] = warnings
        return result

    def set_config(self, existing_bgp_communities_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        have = existing_bgp_communities_facts
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
        # with open('/root/ansible_log.log', 'a+') as fp:
        #     fp.write('comm: want: ' + str(want) + '\n')
        #     fp.write('comm: have: ' + str(have) + '\n')
        #     fp.write('comm: diff: ' + str(diff) + '\n')
        if state == 'overridden':
            commands, requests = self._state_overridden(want, have, diff)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have, diff)
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
        requests = self.get_modify_bgp_community_requests(commands, have)
        if commands and len(requests) > 0:
            commands = update_states(commands, "merged")
        else:
            commands = []

        return commands, requests

    def _state_deleted(self, want, have, diff):
        """ The command generator when state is deleted

        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        # Delete a community
        # https://100.94.81.19/restconf/data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/community-sets/community-set=extest
        # Delete all members but not community
        # https://100.94.81.19/restconf/data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/community-sets/community-set=extest/config/community-member
        # Dete a memeber from the expanded community
        # https://100.94.81.19/restconf/data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/community-sets/community-set=extest/config/community-member=REGEX%3A100.100
        # Delete ALL Bgp_communities and its members
        # https://100.94.81.19/restconf/data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/community-sets
        is_delete_all = False
        # if want is none, then delete ALL
        if not want:
            commands = have
            is_delete_all = True
        else:
            commands = want

        requests = self.get_delete_bgp_communities(commands, have, is_delete_all)

        if commands and len(requests) > 0:
            commands = update_states(commands, "deleted")
        else:
            commands = []

        return commands, requests

    def get_delete_single_bgp_community_member_requests(self, name, type, members):
        requests = []
        for member in members:
            url = "data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:"
            url = url + "bgp-defined-sets/community-sets/community-set={name}/config/{members_param}"
            method = "DELETE"
            memberstr = member
            if type == 'expanded':
                memberstr = 'REGEX:' + member
            members_params = {'community-member': memberstr}
            members_str = urlencode(members_params)
            request = {"path": url.format(name=name, members_param=members_str), "method": method}
            requests.append(request)
        return requests

    def get_delete_all_members_bgp_community_requests(self, name):
        url = "data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:"
        url = url + "bgp-defined-sets/community-sets/community-set={}/config/community-member"
        method = "DELETE"
        request = {"path": url.format(name), "method": method}
        return request

    def get_delete_single_bgp_community_requests(self, name):
        url = "data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/community-sets/community-set={}"
        method = "DELETE"
        request = {"path": url.format(name), "method": method}
        return request

    def get_delete_all_bgp_communities(self, commands):
        url = "data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/community-sets"
        method = "DELETE"
        requests = []
        if commands:
            request = {"path": url, "method": method}
            requests.append(request)
        return requests

    def get_delete_bgp_communities(self, commands, have, is_delete_all):
        # with open('/root/ansible_log.log', 'a+') as fp:
        #     fp.write('bgp_commmunities: delete requests ************** \n')
        requests = []
        if is_delete_all:
            requests = self.get_delete_all_bgp_communities(commands)
        else:
            for cmd in commands:
                name = cmd['name']
                type = cmd['type']
                members = cmd['members']
                if members:
                    if members['regex']:
                        diff_members = []
                        for item in have:
                            if item['name'] == name and item['members']:
                                for member_want in members['regex']:
                                    if str(member_want) in item['members']['regex']:
                                        diff_members.append(member_want)
                        if diff_members:
                            requests.extend(self.get_delete_single_bgp_community_member_requests(name, type, diff_members))
                    else:
                        for item in have:
                            if item['name'] == name:
                                if item['members']:
                                    requests.append(self.get_delete_all_members_bgp_community_requests(name))
                else:
                    for item in have:
                        if item['name'] == name:
                            requests.append(self.get_delete_single_bgp_community_requests(name))

        # with open('/root/ansible_log.log', 'a+') as fp:
        #     fp.write('bgp_commmunities: delete requests' + str(requests) + '\n')
        return requests

    def get_new_add_request(self, conf):
        url = "data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/community-sets"
        method = "PATCH"
        # members = conf['members']
        # members_str = ', '.join(members)
        # members_list = list()
        # for member in members.split(','):
        #     members_list.append(str(member))

        if 'match' not in conf:
            conf['match'] = "ANY"
        # with open('/root/ansible_log.log', 'a+') as fp:
        #     fp.write('bgp_communities: conf' + str(conf) + '\n')
        if 'local_as' in conf and conf['local_as']:
            conf['members']['regex'].append("NO_EXPORT_SUBCONFED")
        if 'no_peer' in conf and conf['no_peer']:
            conf['members']['regex'].append("NOPEER")
        if 'no_export' in conf and conf['no_export']:
            conf['members']['regex'].append("NO_EXPORT")
        if 'no_advertise' in conf and conf['no_advertise']:
            conf['members']['regex'].append("NO_ADVERTISE")
        input_data = {'name': conf['name'], 'members_list': conf['members']['regex'], 'match': conf['match']}
        if conf['type'] == 'expanded':
            input_data['regex'] = "REGEX:"
        else:
            input_data['regex'] = ""
        if conf['permit']:
            input_data['permit'] = "PERMIT"
        else:
            input_data['permit'] = "DENY"
        payload_template = """
                            {
                                "openconfig-bgp-policy:community-sets": {
                                    "community-set": [
                                        {
                                            "community-set-name": "{{name}}",
                                            "config": {
                                                "community-set-name": "{{name}}",
                                                "community-member": [
                                                    {% for member in members_list %}"{{regex}}{{member}}"{%- if not loop.last -%},{% endif %}{%endfor%}
                                                ],
                                                "openconfig-bgp-policy-ext:action": "{{permit}}",
                                                "match-set-options": "{{match}}"
                                            }
                                        }
                                    ]
                                }
                            }"""
        env = jinja2.Environment(autoescape=False)
        t = env.from_string(payload_template)
        intended_payload = t.render(input_data)
        ret_payload = json.loads(intended_payload)
        request = {"path": url, "method": method, "data": ret_payload}
        # with open('/root/ansible_log.log', 'a+') as fp:
        #     fp.write('bgp_communities: request' + str(request) + '\n')
        return request

    def get_modify_bgp_community_requests(self, commands, have):
        requests = []
        if not commands:
            return requests

        for conf in commands:
            for item in have:
                if item['name'] == conf['name']:
                    if 'type' not in conf:
                        conf['type'] = item['type']
                    if 'permit' not in conf:
                        conf['permit'] = item['permit']
                    if 'match' not in conf:
                        conf['match'] = item['match']
                    if 'members' not in conf:
                        conf['members'] = item['members']
            new_req = self.get_new_add_request(conf)
            if new_req:
                requests.append(new_req)
        return requests

#
# -*- coding: utf-8 -*-
# Copyright 2023 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_prefix_lists class
It is in this file that the current configuration (as dict)
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

from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts \
    import Facts

from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils \
    import (
        get_diff,
        update_states,
    )

from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)

# from ansible.module_utils.connection import ConnectionError

TEST_KEYS = [
    {"config": {"afi": "", "name": ""}},
    {"prefixes": {"ge": "", "le": "", "prefix": "", "sequence": ""}}
]

DELETE = "delete"
PATCH = "patch"


class Prefix_lists(ConfigBase):
    """
    The sonic_prefix_lists class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'prefix_lists',
    ]

    prefix_sets_uri = 'data/openconfig-routing-policy:routing-policy/defined-sets/prefix-sets'
    prefix_set_uri = 'data/openconfig-routing-policy:routing-policy/defined-sets/\
prefix-sets/prefix-set'
    prefix_set_delete_uri = 'data/openconfig-routing-policy:routing-policy/defined-sets/\
prefix-sets/prefix-set={}'
    prefix_set_delete_all_prefixes_uri = 'data/openconfig-routing-policy:routing-policy/\
defined-sets/prefix-sets/prefix-set={}/openconfig-routing-policy-ext:extended-prefixes'
    prefix_set_delete_prefix_uri = 'data/openconfig-routing-policy:routing-policy/\
defined-sets/prefix-sets/prefix-set={}/\
openconfig-routing-policy-ext:extended-prefixes/extended-prefix={},{},{}'
    prefix_set_data_path = 'openconfig-routing-policy:prefix-set'
    ext_prefix_set_data_path = 'openconfig-routing-policy-ext:extended-prefixes'

    def __init__(self, module):
        super(Prefix_lists, self).__init__(module)

    def get_prefix_lists_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset,
                                                         self.gather_network_resources)
        prefix_lists_facts = facts['ansible_network_resources'].get('prefix_lists', None)
        if not prefix_lists_facts:
            return []
        return prefix_lists_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()

        existing_prefix_lists_facts = self.get_prefix_lists_facts()
        commands, requests = self.set_config(existing_prefix_lists_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_prefix_lists_facts = self.get_prefix_lists_facts()

        result['before'] = existing_prefix_lists_facts
        if result['changed']:
            result['after'] = changed_prefix_lists_facts

        result['warnings'] = warnings
        return result

    def set_config(self, existing_prefix_lists_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        have = existing_prefix_lists_facts
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
        diff = get_diff(want, have, TEST_KEYS)
        if state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        elif state == 'merged':
            commands, requests = self._state_merged(diff)
        elif state == 'replaced':
            commands, requests = self._state_replaced(diff)
        elif state == 'overridden':
            commands, requests = self._state_overridden(want, have)
        ret_commands = commands
        return ret_commands, requests

    def _state_merged(self, diff):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = diff
        requests = self.get_modify_prefix_lists_requests(commands)
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
        commands = list()
        if not want or want == []:
            commands = have
            requests = self.get_delete_all_prefix_list_cfg_requests()
        else:
            commands = want
            requests = self.get_delete_prefix_lists_cfg_requests(commands, have)
        if commands and len(requests) > 0:
            commands = update_states(commands, "deleted")
        else:
            commands = []
        return commands, requests

    def _state_replaced(self, diff):
        """ The command generator when state is replaced
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = diff
        requests = self.get_modify_prefix_lists_requests(commands)
        if commands and len(requests) > 0:
            commands = update_states(commands, "replaced")
        else:
            commands = []

        return commands, requests

    def _state_overridden(self, want, have):
        """ The command generator when state is overridden
        :param want: the desired configuration as a dictionary
        :param have: the current configuration as a dictionary
        :param diff: the difference between want and have
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        requests = []
        self.sort_lists_in_config(want)
        self.sort_lists_in_config(have)

        if have and have != want:
            del_requests = self.get_delete_all_prefix_list_cfg_requests()
            requests.extend(del_requests)
            commands.extend(update_states(have, "deleted"))
            have = []

        if not have and want:
            mod_commands = want
            mod_requests = self.get_modify_prefix_lists_requests(mod_commands)

            if len(mod_requests) > 0:
                requests.extend(mod_requests)
                commands.extend(update_states(mod_commands, "overridden"))

        return commands, requests

    def get_modify_prefix_lists_requests(self, commands):
        '''Traverse the input list of configuration "modify" commands obtained
        from parsing the input playbook parameters. For each command,
        create and return the appropriate set of REST API requests to modify
        the prefix set specified by the current command.'''

        requests = []
        if not commands:
            return requests

        # Create URL and payload
        prefix_set_payload_list = []
        for command in commands:
            prefix_set_payload = self.get_modify_single_prefix_set_request(command)
            if prefix_set_payload:
                prefix_set_payload_list.append(prefix_set_payload)
        prefix_set_data = {self.prefix_set_data_path: prefix_set_payload_list}
        request = {'path': self.prefix_set_uri, 'method': PATCH, 'data': prefix_set_data}
        requests.append(request)
        return requests

    def get_modify_single_prefix_set_request(self, command):
        '''Create and return the appropriate set of REST API requests to modfy
        the prefix set configuration specified by the current "command".'''

        request = {}
        if not command:
            return request

        conf_afi = command.get('afi', None)
        conf_name = command.get('name', None)
        if not conf_afi or not conf_name:
            return request

        prefix_set_payload_header = {'name': conf_name,
                                     'config': {'name': conf_name, 'mode': conf_afi.upper()}}

        pfx_conf_list = []
        prefixes = command.get('prefixes', None)

        if prefixes:
            for prefix in prefixes:
                pfx_payload = self.get_modify_prefix_request(prefix, conf_afi)
                if pfx_payload:
                    pfx_conf_list.append(pfx_payload)

        ext_prefix_list_payload = {'extended-prefix': pfx_conf_list}
        ext_prefix_list_data = {self.ext_prefix_set_data_path: ext_prefix_list_payload}

        prefix_set_payload = prefix_set_payload_header
        prefix_set_payload.update(ext_prefix_list_data)
        return prefix_set_payload

    def get_modify_prefix_request(self, prefix, conf_afi):
        '''Create a REST API request to update/merge/create  the prefix specified by the
        "prefix" input parameter.'''

        pfx_payload = {}
        prefix_val = prefix.get('prefix', None)
        sequence = prefix.get('sequence', None)
        action = prefix.get('action', None)
        if not prefix_val or not sequence or not action:
            return None

        prefix_net = self.set_ipaddress_net_attrs(prefix_val, conf_afi)
        ge = prefix.get('ge', None)
        le = prefix.get('le', None)
        pfx_payload['ip-prefix'] = prefix_val
        pfx_payload['sequence-number'] = sequence
        masklength_range_str = self.get_masklength_range_string(ge, le, prefix_net)
        pfx_payload['masklength-range'] = masklength_range_str
        pfx_config = {}
        pfx_config['sequence-number'] = sequence
        pfx_config['ip-prefix'] = prefix_val
        pfx_config['masklength-range'] = pfx_payload['masklength-range']
        pfx_config['openconfig-routing-policy-ext:action'] = action.upper()
        pfx_payload['config'] = pfx_config

        return pfx_payload

    def get_create_prefix_lists_cfg_requests(self, commands):
        '''Placeholder function  Modify this function if necessary to enable
        separate actions for "CREATE" vs "MERGE" ("PATCH") requests'''

        return self.get_modify_prefix_lists_requests(commands)

    def get_delete_prefix_lists_cfg_requests(self, commands, have):
        '''Traverse the input list of configuration "delete" commands obtained
        from parsing the input playbook parameters. For each command,
        create and return the appropriate set of REST API requests to delete
        the prefix set configuration specified by the current "command".'''
        requests = []
        for command in commands:
            new_requests = self.get_delete_single_prefix_cfg_requests(command, have)
            if new_requests and len(new_requests) > 0:
                requests.extend(new_requests)
        return requests

    def get_delete_single_prefix_cfg_requests(self, command, have):
        '''Create and return the appropriate set of REST API requests to delete
        the prefix set configuration specified by the current "command".'''

        requests = list()
        pfx_set_name = command.get('name', None)
        if not pfx_set_name:
            return requests

        cfg_prefix_set = self.prefix_set_in_config(pfx_set_name, have)
        if not cfg_prefix_set:
            return requests

        prefixes = command.get('prefixes', None)
        if not prefixes or prefixes == []:
            requests = self.get_delete_prefix_set_cfg(command)
        else:
            requests = self.get_delete_one_prefix_list_cfg(cfg_prefix_set, command)
        return requests

    def get_delete_prefix_set_cfg(self, command):
        '''Create and return a REST API request to delete the prefix set specified
        by the current "command".'''

        pfx_set_name = command.get('name', None)

        requests = [{'path': self.prefix_set_delete_uri.format(pfx_set_name), 'method': DELETE}]
        return requests

    def get_delete_one_prefix_list_cfg(self, cfg_prefix_set, command):
        '''Create the list of REST API prefix deletion requests needed for deletion
        of the the requested set of prefixes from the currently configured
        prefix set specified by "cfg_prefix_set".'''

        pfx_delete_cfg_list = list()
        prefixes = command.get('prefixes', None)

        for prefix in prefixes:
            pfx_delete_cfg = self.prefix_get_delete_single_prefix_cfg(prefix,
                                                                      cfg_prefix_set,
                                                                      command)
            if pfx_delete_cfg and len(pfx_delete_cfg) > 0:
                pfx_delete_cfg_list.append(pfx_delete_cfg)
        return pfx_delete_cfg_list

    def prefix_get_delete_single_prefix_cfg(self, prefix, cfg_prefix_set, command):
        '''Create the REST API request to delete the prefix specified by the "prefix"
        input parameter from the configured prefix set specified by "cfg_prefix_set".
        Return an empty request if the prefix is not present in the confgured prefix set.'''

        pfx_delete_cfg_request = {}
        if not self.prefix_in_prefix_list_cfg(prefix, cfg_prefix_set):
            return pfx_delete_cfg_request

        conf_afi = command.get('afi', None)
        if not conf_afi:
            return pfx_delete_cfg_request

        pfx_set_name = command.get('name', None)
        pfx_seq = prefix.get("sequence", None)
        pfx_val = prefix.get("prefix", None)
        pfx_ge = prefix.get("ge", None)
        pfx_le = prefix.get("le", None)

        if not pfx_seq or not pfx_val:
            return pfx_delete_cfg_request

        prefix_net = self.set_ipaddress_net_attrs(pfx_val, conf_afi)
        masklength_range_str = self.get_masklength_range_string(pfx_ge, pfx_le, prefix_net)
        prefix_string = pfx_val.replace("/", "%2F")
        extended_pfx_cfg_str = self.prefix_set_delete_prefix_uri.format(pfx_set_name,
                                                                        int(pfx_seq),
                                                                        prefix_string,
                                                                        masklength_range_str)
        pfx_delete_cfg_request = {'path': extended_pfx_cfg_str, 'method': DELETE}
        return pfx_delete_cfg_request

    def get_delete_all_prefix_list_cfg_requests(self):
        '''Delete all prefix list configuration'''
        requests = list()
        requests = [{'path': self.prefix_sets_uri, 'method': DELETE}]
        return requests

    def get_masklength_range_string(self, pfx_ge, pfx_le, prefix_net):
        '''Determine the "masklength range" string required for the openconfig
        REST API to configure the affected prefix.'''
        if not pfx_ge and not pfx_le:
            masklength_range_string = "exact"
        elif pfx_ge and not pfx_le:
            masklength_range_string = str(pfx_ge) + ".." + str(prefix_net['max_prefixlen'])
        elif not pfx_ge and pfx_le:
            masklength_range_string = str(prefix_net['prefixlen']) + ".." + str(pfx_le)
        else:
            masklength_range_string = str(pfx_ge) + ".." + str(pfx_le)

        return masklength_range_string

    def prefix_set_in_config(self, pfx_set_name, have):
        '''Determine if the prefix set specifid by "pfx_set_name" is present in
        the current switch configuration. If it is present, return the "found"
        prefix set. (Otherwise, return "None"'''
        for cfg_prefix_set in have:
            cfg_prefix_set_name = cfg_prefix_set.get('name', None)
            if cfg_prefix_set_name and cfg_prefix_set_name == pfx_set_name:
                return cfg_prefix_set

        return None

    def prefix_in_prefix_list_cfg(self, prefix, cfg_prefix_set):
        '''Determine, based on the keys, if the "target" prefix specified by the "prefix"
        input parameter is present in the currently configured prefix set specified
        ty the "cfg_prefix_set" input parameter. Return "True" if the prifix is found,
        or "False" if it isn't.'''
        req_pfx = prefix.get("prefix", None)
        req_seq = prefix.get("sequence", None)
        req_ge = prefix.get("ge", None)
        req_le = prefix.get("le", None)

        cfg_prefix_list = cfg_prefix_set.get("prefixes", None)
        if not cfg_prefix_list:     # The configured prefix set has no prefix list
            return False

        for cfg_prefix in cfg_prefix_list:
            cfg_pfx = cfg_prefix.get("prefix", None)
            cfg_seq = cfg_prefix.get("sequence", None)
            cfg_ge = cfg_prefix.get("ge", None)
            cfg_le = cfg_prefix.get("le", None)

            # Check for matching key attributes
            if not (req_pfx and cfg_pfx and req_pfx == cfg_pfx):
                continue
            if not (req_seq and cfg_seq and req_seq == cfg_seq):
                continue

            # Check for ge match
            if not req_ge:
                if cfg_ge:
                    continue
            else:
                if not cfg_ge or req_ge != cfg_ge:
                    continue

            # Check for le match
            if not req_le:
                if cfg_le:
                    continue
            else:
                if not cfg_le or req_le != cfg_le:
                    continue

            # All key attributes match for this cfg_prefix
            return True

        # No matching configured prefixes were found in the prefix set.
        return False

    def set_ipaddress_net_attrs(self, prefix_val, conf_afi):
        '''Create and return a dictionary containing the values for any prefix-related
        attributes needed for handling of prefix configuration requests. NOTE: This
        method should be replaced with use of the Python "ipaddress" module after
        Ansible drops downward compatibility support for Python 2.7.'''

        prefix_net = dict()
        if conf_afi == 'ipv4':
            prefix_net['max_prefixlen'] = 32
        else:   # Assuming IPv6 for this case
            prefix_net['max_prefixlen'] = 128

        prefix_net['prefixlen'] = int(prefix_val.split("/")[1])
        return prefix_net

    def sort_lists_in_config(self, config):
        if config:
            config.sort(key=self.get_name)
            for cfg in config:
                if 'prefixes' in cfg and cfg['prefixes']:
                    cfg['prefixes'].sort(key=lambda x: (x['sequence'], x['action'], x['prefix']))

    def get_name(self, name):
        return name.get('name')

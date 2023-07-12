#
# -*- coding: utf-8 -*-
# Copyright 2023 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_mac class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    update_states,
    get_diff,
    get_replaced_config,
    send_requests
)

NETWORK_INSTANCE_PATH = '/data/openconfig-network-instance:network-instances/network-instance'
PATCH = 'patch'
DELETE = 'delete'
TEST_KEYS = [
    {'config': {'vrf_name': ''}},
    {'mac_table_entries': {'mac_address': '', 'vlan_id': ''}}
]


class Mac(ConfigBase):
    """
    The sonic_mac class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'mac',
    ]

    def __init__(self, module):
        super(Mac, self).__init__(module)

    def get_mac_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        mac_facts = facts['ansible_network_resources'].get('mac')
        if not mac_facts:
            return []
        return mac_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = []
        commands = []

        existing_mac_facts = self.get_mac_facts()
        commands, requests = self.set_config(existing_mac_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_mac_facts = self.get_mac_facts()

        result['before'] = existing_mac_facts
        if result['changed']:
            result['after'] = changed_mac_facts

        result['warnings'] = warnings
        return result

    def set_config(self, existing_mac_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        have = existing_mac_facts
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

        if state == 'overridden':
            commands, requests = self._state_overridden(want, have)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        elif state == 'merged':
            commands, requests = self._state_merged(diff)
        elif state == 'replaced':
            commands, requests = self._state_replaced(want, have, diff)
        return commands, requests

    def _state_replaced(self, want, have, diff):
        """ The command generator when state is replaced
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        replaced_config = get_replaced_config(want, have, TEST_KEYS)

        if replaced_config:
            self.sort_lists_in_config(replaced_config)
            self.sort_lists_in_config(have)
            is_delete_all = (replaced_config == have)
            requests = self.get_delete_mac_requests(replaced_config, have, is_delete_all)
            send_requests(self._module, requests)

            commands = want
        else:
            commands = diff

        requests = []

        if commands:
            requests = self.get_modify_mac_requests(commands)

            if len(requests) > 0:
                commands = update_states(commands, "replaced")
            else:
                commands = []
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
        self.sort_lists_in_config(want)
        self.sort_lists_in_config(have)

        if have and have != want:
            is_delete_all = True
            requests = self.get_delete_mac_requests(have, None, is_delete_all)
            send_requests(self._module, requests)
            have = []

        commands = []
        requests = []

        if not have and want:
            commands = want
            requests = self.get_modify_mac_requests(commands)

            if len(requests) > 0:
                commands = update_states(commands, "overridden")
            else:
                commands = []

        return commands, requests

    def _state_merged(self, diff):
        """ The command generator when state is merged
        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = diff
        requests = self.get_modify_mac_requests(commands)

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
        is_delete_all = False
        # if want is none, then delete ALL
        if not want:
            commands = have
            is_delete_all = True
        else:
            commands = want

        commands = self.remove_default_entries(commands)
        requests = self.get_delete_mac_requests(commands, have, is_delete_all)

        if commands and len(requests) > 0:
            commands = update_states(commands, "deleted")
        else:
            commands = []

        return commands, requests

    def get_modify_mac_requests(self, commands):

        requests = []

        if not commands:
            return requests

        for cmd in commands:
            vrf_name = cmd.get('vrf_name', None)
            mac = cmd.get('mac', {})
            if mac:
                aging_time = mac.get('aging_time', None)
                dampening_interval = mac.get('dampening_interval', None)
                dampening_threshold = mac.get('dampening_threshold', None)
                mac_table_entries = mac.get('mac_table_entries', [])
                fdb_dict = {}
                dampening_cfg_dict = {}
                if aging_time:
                    fdb_dict['config'] = {'mac-aging-time': aging_time}
                if dampening_interval:
                    dampening_cfg_dict['interval'] = dampening_interval
                if dampening_threshold:
                    dampening_cfg_dict['threshold'] = dampening_threshold
                if mac_table_entries:
                    entry_list = []
                    entries_dict = {}
                    mac_table_dict = {}
                    for entry in mac_table_entries:
                        entry_dict = {}
                        entry_cfg_dict = {}
                        mac_address = entry.get('mac_address', None)
                        vlan_id = entry.get('vlan_id', None)
                        interface = entry.get('interface', None)
                        if mac_address:
                            entry_dict['mac-address'] = mac_address
                            entry_cfg_dict['mac-address'] = mac_address
                        if vlan_id:
                            entry_dict['vlan'] = vlan_id
                            entry_cfg_dict['vlan'] = vlan_id
                        if entry_cfg_dict:
                            entry_dict['config'] = entry_cfg_dict
                        if interface:
                            entry_dict['interface'] = {'interface-ref': {'config': {'interface': interface, 'subinterface': 0}}}
                        if entry_dict:
                            entry_list.append(entry_dict)
                    if entry_list:
                        entries_dict['entry'] = entry_list
                    if entries_dict:
                        mac_table_dict['entries'] = entries_dict
                    if mac_table_dict:
                        fdb_dict['mac-table'] = mac_table_dict
                if fdb_dict:
                    url = '%s=%s/fdb' % (NETWORK_INSTANCE_PATH, vrf_name)
                    payload = {'openconfig-network-instance:fdb': fdb_dict}
                    requests.append({'path': url, 'method': PATCH, 'data': payload})
                if dampening_cfg_dict:
                    url = '%s=%s/openconfig-mac-dampening:mac-dampening' % (NETWORK_INSTANCE_PATH, vrf_name)
                    payload = {'openconfig-mac-dampening:mac-dampening': {'config': dampening_cfg_dict}}
                    requests.append({'path': url, 'method': PATCH, 'data': payload})

        return requests

    def get_delete_mac_requests(self, commands, have, is_delete_all):
        requests = []

        for cmd in commands:
            vrf_name = cmd.get('vrf_name', None)
            if vrf_name and is_delete_all:
                requests.extend(self.get_delete_all_mac_requests(vrf_name))
            else:
                mac = cmd.get('mac', {})
                if mac:
                    aging_time = mac.get('aging_time', None)
                    dampening_interval = mac.get('dampening_interval', None)
                    dampening_threshold = mac.get('dampening_threshold', None)
                    mac_table_entries = mac.get('mac_table_entries', [])
                    if mac_table_entries:
                        for entry in mac_table_entries:
                            mac_address = entry.get('mac_address', None)
                            vlan_id = entry.get('vlan_id', None)
                            interface = entry.get('interface', None)

                            for cfg in have:
                                cfg_vrf_name = cfg.get('vrf_name', None)
                                cfg_mac = cfg.get('mac', {})
                                if cfg_mac:
                                    cfg_aging_time = cfg_mac.get('aging_time', None)
                                    cfg_dampening_interval = cfg_mac.get('dampening_interval', None)
                                    cfg_dampening_threshold = cfg_mac.get('dampening_threshold', None)
                                    cfg_mac_table_entries = cfg_mac.get('mac_table_entries', [])
                                    if cfg_mac_table_entries:
                                        for cfg_entry in cfg_mac_table_entries:
                                            cfg_mac_address = cfg_entry.get('mac_address', None)
                                            cfg_vlan_id = cfg_entry.get('vlan_id', None)
                                            cfg_interface = cfg_entry.get('interface', None)
                                            if vrf_name and vrf_name == cfg_vrf_name:
                                                if aging_time and aging_time == cfg_aging_time:
                                                    requests.append(self.get_delete_fdb_cfg_attr(vrf_name, 'mac-aging-time'))
                                                if dampening_interval and dampening_interval == cfg_dampening_interval:
                                                    requests.append(self.get_delete_mac_dampening_attr(vrf_name, 'interval'))
                                                if dampening_threshold and dampening_threshold == cfg_dampening_threshold:
                                                    requests.append(self.get_delete_mac_dampening_attr(vrf_name, 'threshold'))
                                                if mac_address and vlan_id and mac_address == cfg_mac_address and vlan_id == cfg_vlan_id:
                                                    if interface and interface == cfg_interface:
                                                        requests.append(self.get_delete_mac_table_intf(vrf_name, mac_address, vlan_id))
                                                    elif not interface:
                                                        requests.append(self.get_delete_mac_table_entry(vrf_name, mac_address, vlan_id))

        return requests

    def get_delete_all_mac_requests(self, vrf_name):
        requests = []
        url = '%s=%s/fdb' % (NETWORK_INSTANCE_PATH, vrf_name)
        requests.append({'path': url, 'method': DELETE})
        url = '%s=%s/openconfig-mac-dampening:mac-dampening' % (NETWORK_INSTANCE_PATH, vrf_name)
        requests.append({'path': url, 'method': DELETE})

        return requests

    def get_delete_fdb_cfg_attr(self, vrf_name, attr):
        url = '%s=%s/fdb/config/%s' % (NETWORK_INSTANCE_PATH, vrf_name, attr)
        request = {'path': url, 'method': DELETE}

        return request

    def get_delete_mac_dampening_attr(self, vrf_name, attr):
        url = '%s=%s/openconfig-mac-dampening:mac-dampening/config/%s' % (NETWORK_INSTANCE_PATH, vrf_name, attr)
        request = {'path': url, 'method': DELETE}

        return request

    def get_delete_mac_table_entry(self, vrf_name, mac_address, vlan_id):
        url = '%s=%s/fdb/mac-table/entries/entry=%s,%s' % (NETWORK_INSTANCE_PATH, vrf_name, mac_address, vlan_id)
        request = {'path': url, 'method': DELETE}

        return request

    def get_delete_mac_table_intf(self, vrf_name, mac_address, vlan_id):
        url = '%s=%s/fdb/mac-table/entries/entry=%s,%s/interface' % (NETWORK_INSTANCE_PATH, vrf_name, mac_address, vlan_id)
        request = {'path': url, 'method': DELETE}

        return request

    def get_mac_vrf_name(self, vrf_name):
        return vrf_name.get('vrf_name')

    def sort_lists_in_config(self, config):
        if config:
            config.sort(key=self.get_mac_vrf_name)
        for cfg in config:
            if 'mac' in cfg and cfg['mac'] is not None:
                if 'mac_table_entries' in cfg['mac'] and cfg['mac']['mac_table_entries'] is not None:
                    cfg['mac']['mac_table_entries'].sort(key=lambda x: (x['mac_address'], x['vlan_id']))

    def remove_default_entries(self, data):
        new_data = []

        if not data:
            return new_data

        for conf in data:
            new_conf = {}
            vrf_name = conf.get('vrf_name', None)
            mac = conf.get('mac', None)
            if mac:
                new_mac = {}
                aging_time = mac.get('aging_time', None)
                dampening_interval = mac.get('dampening_interval', None)
                dampening_threshold = mac.get('dampening_threshold', None)
                mac_table_entries = mac.get('mac_table_entries', None)

                if aging_time and aging_time != 600:
                    new_mac['aging_time'] = aging_time
                if dampening_interval and dampening_interval != 5:
                    new_mac['dampening_interval'] = dampening_interval
                if dampening_threshold and dampening_threshold != 5:
                    new_mac['dampening_threshold'] = dampening_threshold
                if mac_table_entries is not None:
                    new_mac['mac_table_entries'] = mac_table_entries
                if new_mac:
                    new_conf['mac'] = new_mac
                    new_conf['vrf_name'] = vrf_name
            if new_conf:
                new_data.append(new_conf)

        return new_data

#
# -*- coding: utf-8 -*-
# Copyright 2020 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_mclag class
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
    to_list
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    update_states,
    get_diff,
    get_normalize_interface_name,
    normalize_interface_name
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible.module_utils.connection import ConnectionError

PATCH = 'patch'
DELETE = 'delete'

TEST_KEYS = [
    {'config': {'domain_id': ''}},
    {'vlans': {'vlan': ''}},
    {'portchannels': {'lag': ''}},
]


class Mclag(ConfigBase):
    """
    The sonic_mclag class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'mclag',
    ]

    def __init__(self, module):
        super(Mclag, self).__init__(module)

    def get_mclag_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        mclag_facts = facts['ansible_network_resources'].get('mclag')
        if not mclag_facts:
            return []
        return mclag_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()
        commands = list()

        existing_mclag_facts = self.get_mclag_facts()
        commands, requests = self.set_config(existing_mclag_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                self.edit_config(requests)
            result['changed'] = True
        result['commands'] = commands

        changed_mclag_facts = self.get_mclag_facts()

        result['before'] = existing_mclag_facts
        if result['changed']:
            result['after'] = changed_mclag_facts

        result['warnings'] = warnings
        return result

    def edit_config(self, requests):
        try:
            response = edit_config(self._module, to_request(self._module, requests))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

    def set_config(self, existing_mclag_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        if want:
            peer_link = want.get("peer_link", None)
            if peer_link:
                want['peer_link'] = get_normalize_interface_name(want['peer_link'], self._module)
            unique_ip = want.get('unique_ip', None)
            if unique_ip:
                vlans_list = unique_ip['vlans']
                if vlans_list:
                    normalize_interface_name(vlans_list, self._module, 'vlan')
            peer_gateway = want.get('peer_gateway', None)
            if peer_gateway:
                vlans_list = peer_gateway['vlans']
                if vlans_list:
                    normalize_interface_name(vlans_list, self._module, 'vlan')
            members = want.get('members', None)
            if members:
                portchannels_list = members['portchannels']
                if portchannels_list:
                    normalize_interface_name(portchannels_list, self._module, 'lag')
        have = existing_mclag_facts
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
        if state == 'deleted':
            commands = self._state_deleted(want, have)
        elif state == 'merged':
            diff = get_diff(want, have, TEST_KEYS)
            commands = self._state_merged(want, have, diff)
        return commands

    def _state_merged(self, want, have, diff):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        requests = []
        commands = []
        if diff:
            requests = self.get_create_mclag_request(want, diff)
            if len(requests) > 0:
                commands = update_states(diff, "merged")
        return commands, requests

    def _state_deleted(self, want, have):
        """ The command generator when state is deleted

        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        commands = []
        requests = []
        if not want:
            if have:
                requests = self.get_delete_all_mclag_domain_request(have)
                if len(requests) > 0:
                    commands = update_states(have, "deleted")
        else:
            new_have = self.remove_default_entries(have)
            d_diff = get_diff(want, new_have, TEST_KEYS, is_skeleton=True)
            diff_want = get_diff(want, d_diff, TEST_KEYS, is_skeleton=True)
            if diff_want:
                requests = self.get_delete_mclag_attribute_request(want, diff_want)
                if len(requests) > 0:
                    commands = update_states(diff_want, "deleted")
        return commands, requests

    def remove_default_entries(self, data):
        new_data = {}
        if not data:
            return new_data
        else:
            default_val_dict = {
                'keepalive': 1,
                'session_timeout': 30,
                'delay_restore': 300
            }
            for key, val in data.items():
                if not (val is None or (key in default_val_dict and val == default_val_dict[key])):
                    new_data[key] = val

            return new_data

    def get_delete_mclag_attribute_request(self, want, command):
        requests = []
        url_common = 'data/openconfig-mclag:mclag/mclag-domains/mclag-domain=%s/config' % (want["domain_id"])
        method = DELETE
        if 'source_address' in command and command["source_address"] is not None:
            url = url_common + '/source-address'
            request = {'path': url, 'method': method}
            requests.append(request)
        if 'peer_address' in command and command["peer_address"] is not None:
            url = url_common + '/peer-address'
            request = {'path': url, 'method': method}
            requests.append(request)
        if 'peer_link' in command and command["peer_link"] is not None:
            url = url_common + '/peer-link'
            request = {'path': url, 'method': method}
            requests.append(request)
        if 'keepalive' in command and command["keepalive"] is not None:
            url = url_common + '/keepalive-interval'
            request = {'path': url, 'method': method}
            requests.append(request)
        if 'session_timeout' in command and command["session_timeout"] is not None:
            url = url_common + '/session-timeout'
            request = {'path': url, 'method': method}
            requests.append(request)
        if 'system_mac' in command and command["system_mac"] is not None:
            url = url_common + '/mclag-system-mac'
            request = {'path': url, 'method': method}
            requests.append(request)
        if 'delay_restore' in command and command['delay_restore'] is not None:
            url = url_common + '/delay-restore'
            request = {'path': url, 'method': method}
            requests.append(request)
        if 'peer_gateway' in command and command['peer_gateway'] is not None:
            if command['peer_gateway']['vlans'] is None:
                request = {'path': 'data/openconfig-mclag:mclag/vlan-ifs/vlan-if', 'method': method}
                requests.append(request)
            elif command['peer_gateway']['vlans'] is not None:
                for each in command['peer_gateway']['vlans']:
                    if each:
                        peer_gateway_url = 'data/openconfig-mclag:mclag/vlan-ifs/vlan-if=%s' % (each['vlan'])
                        request = {'path': peer_gateway_url, 'method': method}
                        requests.append(request)
        if 'unique_ip' in command and command['unique_ip'] is not None:
            if command['unique_ip']['vlans'] is None:
                request = {'path': 'data/openconfig-mclag:mclag/vlan-interfaces/vlan-interface', 'method': method}
                requests.append(request)
            elif command['unique_ip']['vlans'] is not None:
                for each in command['unique_ip']['vlans']:
                    if each:
                        unique_ip_url = 'data/openconfig-mclag:mclag/vlan-interfaces/vlan-interface=%s' % (each['vlan'])
                        request = {'path': unique_ip_url, 'method': method}
                        requests.append(request)
        if 'members' in command and command['members'] is not None:
            if command['members']['portchannels'] is None:
                request = {'path': 'data/openconfig-mclag:mclag/interfaces/interface', 'method': method}
                requests.append(request)
            elif command['members']['portchannels'] is not None:
                for each in command['members']['portchannels']:
                    if each:
                        portchannel_url = 'data/openconfig-mclag:mclag/interfaces/interface=%s' % (each['lag'])
                        request = {'path': portchannel_url, 'method': method}
                        requests.append(request)
        if 'gateway_mac' in command and command['gateway_mac'] is not None:
            request = {'path': 'data/openconfig-mclag:mclag/mclag-gateway-macs/mclag-gateway-mac', 'method': method}
            requests.append(request)
        return requests

    def get_delete_all_mclag_domain_request(self, have):
        requests = []
        path = 'data/openconfig-mclag:mclag/mclag-domains'
        method = DELETE
        if have.get('peer_gateway'):
            request = {'path': 'data/openconfig-mclag:mclag/vlan-ifs/vlan-if', 'method': method}
            requests.append(request)
        if have.get('unique_ip'):
            request = {'path': 'data/openconfig-mclag:mclag/vlan-interfaces/vlan-interface', 'method': method}
            requests.append(request)
        if have.get('gateway_mac'):
            request = {'path': 'data/openconfig-mclag:mclag/mclag-gateway-macs/mclag-gateway-mac', 'method': method}
            requests.append(request)
        request = {'path': path, 'method': method}
        requests.append(request)
        return requests

    def get_create_mclag_request(self, want, commands):
        requests = []
        path = 'data/openconfig-mclag:mclag/mclag-domains/mclag-domain'
        method = PATCH
        payload = self.build_create_payload(want, commands)
        if payload:
            request = {'path': path, 'method': method, 'data': payload}
            requests.append(request)
        if 'gateway_mac' in commands and commands['gateway_mac'] is not None:
            gateway_mac_path = 'data/openconfig-mclag:mclag/mclag-gateway-macs/mclag-gateway-mac'
            gateway_mac_method = PATCH
            gateway_mac_payload = {
                'openconfig-mclag:mclag-gateway-mac': [{
                    'gateway-mac': commands['gateway_mac'],
                    'config': {'gateway-mac': commands['gateway_mac']}
                }]
            }
            request = {'path': gateway_mac_path, 'method': gateway_mac_method, 'data': gateway_mac_payload}
            requests.append(request)
        if 'unique_ip' in commands and commands['unique_ip'] is not None:
            if commands['unique_ip']['vlans'] and commands['unique_ip']['vlans'] is not None:
                unique_ip_path = 'data/openconfig-mclag:mclag/vlan-interfaces/vlan-interface'
                unique_ip_method = PATCH
                unique_ip_payload = self.build_create_unique_ip_payload(commands['unique_ip']['vlans'])
                request = {'path': unique_ip_path, 'method': unique_ip_method, 'data': unique_ip_payload}
                requests.append(request)
        if 'peer_gateway' in commands and commands['peer_gateway'] is not None:
            if commands['peer_gateway']['vlans'] and commands['peer_gateway']['vlans'] is not None:
                peer_gateway_path = 'data/openconfig-mclag:mclag/vlan-ifs/vlan-if'
                peer_gateway_method = PATCH
                peer_gateway_payload = self.build_create_peer_gateway_payload(commands['peer_gateway']['vlans'])
                request = {'path': peer_gateway_path, 'method': peer_gateway_method, 'data': peer_gateway_payload}
                requests.append(request)
        if 'members' in commands and commands['members'] is not None:
            if commands['members']['portchannels'] and commands['members']['portchannels'] is not None:
                portchannel_path = 'data/openconfig-mclag:mclag/interfaces/interface'
                portchannel_method = PATCH
                portchannel_payload = self.build_create_portchannel_payload(want, commands['members']['portchannels'])
                request = {'path': portchannel_path, 'method': portchannel_method, 'data': portchannel_payload}
                requests.append(request)
        return requests

    def build_create_payload(self, want, commands):
        temp = {}
        if 'session_timeout' in commands and commands['session_timeout'] is not None:
            temp['session-timeout'] = commands['session_timeout']
        if 'keepalive' in commands and commands['keepalive'] is not None:
            temp['keepalive-interval'] = commands['keepalive']
        if 'source_address' in commands and commands['source_address'] is not None:
            temp['source-address'] = commands['source_address']
        if 'peer_address' in commands and commands['peer_address'] is not None:
            temp['peer-address'] = commands['peer_address']
        if 'peer_link' in commands and commands['peer_link'] is not None:
            temp['peer-link'] = str(commands['peer_link'])
        if 'system_mac' in commands and commands['system_mac'] is not None:
            temp['openconfig-mclag:mclag-system-mac'] = str(commands['system_mac'])
        if 'delay_restore' in commands and commands['delay_restore'] is not None:
            temp['delay-restore'] = commands['delay_restore']
        mclag_dict = {}
        if temp:
            domain_id = {"domain-id": want["domain_id"]}
            mclag_dict.update(domain_id)
            config = {"config": temp}
            mclag_dict.update(config)
            payload = {"openconfig-mclag:mclag-domain": [mclag_dict]}
        else:
            payload = {}
        return payload

    def build_create_unique_ip_payload(self, commands):
        payload = {"openconfig-mclag:vlan-interface": []}
        for each in commands:
            payload['openconfig-mclag:vlan-interface'].append({"name": each['vlan'], "config": {"name": each['vlan'], "unique-ip-enable": "ENABLE"}})
        return payload

    def build_create_peer_gateway_payload(self, commands):
        payload = {"openconfig-mclag:vlan-if": []}
        for each in commands:
            payload['openconfig-mclag:vlan-if'].append({"name": each['vlan'], "config": {"name": each['vlan'], "peer-gateway-enable": "ENABLE"}})
        return payload

    def build_create_portchannel_payload(self, want, commands):
        payload = {"openconfig-mclag:interface": []}
        for each in commands:
            payload['openconfig-mclag:interface'].append({"name": each['lag'], "config": {"name": each['lag'], "mclag-domain-id": want['domain_id']}})
        return payload

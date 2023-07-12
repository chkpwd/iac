#
# -*- coding: utf-8 -*-
# © Copyright 2020 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_vxlans class
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
    get_diff,
    update_states,
    get_replaced_config,
    send_requests
)
from ansible.module_utils.connection import ConnectionError

PATCH = 'patch'
DELETE = 'delete'
test_keys = [
    {'vlan_map': {'vlan': '', 'vni': ''}},
    {'vrf_map': {'vni': '', 'vrf': ''}},
]


class Vxlans(ConfigBase):
    """
    The sonic_vxlans class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'vxlans',
    ]

    def __init__(self, module):
        super(Vxlans, self).__init__(module)

    def get_vxlans_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        vxlans_facts = facts['ansible_network_resources'].get('vxlans')
        if not vxlans_facts:
            return []
        return vxlans_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()

        existing_vxlans_facts = self.get_vxlans_facts()
        commands, requests = self.set_config(existing_vxlans_facts)

        if commands and requests:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_vxlans_facts = self.get_vxlans_facts()

        result['before'] = existing_vxlans_facts
        if result['changed']:
            result['after'] = changed_vxlans_facts

        result['warnings'] = warnings
        return result

    def set_config(self, existing_vxlans_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        have = existing_vxlans_facts
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

        diff = get_diff(want, have, test_keys)

        if state == 'overridden':
            commands, requests = self._state_overridden(want, have)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have, diff)
        elif state == 'merged':
            commands, requests = self._state_merged(want, have, diff)
        elif state == 'replaced':
            commands, requests = self._state_replaced(want, have, diff)

        return commands, requests

    def _state_replaced(self, want, have, diff):
        """ The command generator when state is replaced

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        requests = []
        replaced_config = get_replaced_config(want, have, test_keys)

        if replaced_config:
            self.sort_lists_in_config(replaced_config)
            self.sort_lists_in_config(have)
            is_delete_all = (replaced_config == have)
            if is_delete_all:
                requests = self.get_delete_all_vxlan_request(have)
            else:
                requests = self.get_delete_vxlan_request(replaced_config, have)

            send_requests(self._module, requests)
            commands = want
        else:
            commands = diff

        requests = []

        if commands:
            requests = self.get_create_vxlans_request(commands, have)
            if len(requests) > 0:
                commands = update_states(commands, "replaced")
            else:
                commands = []
        else:
            commands = []

        return commands, requests

    def _state_overridden(self, want, have):
        """ The command generator when state is overridden

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        self.sort_lists_in_config(want)
        self.sort_lists_in_config(have)

        if have and have != want:
            requests = self.get_delete_all_vxlan_request(have)
            send_requests(self._module, requests)

            have = []

        commands = []
        requests = []

        if not have and want:
            commands = want
            requests = self.get_create_vxlans_request(commands, have)

            if len(requests) > 0:
                commands = update_states(commands, "overridden")
            else:
                commands = []

        return commands, requests

    def _state_merged(self, want, have, diff):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration at position-0
                  Requests necessary to merge to the current configuration
                  at position-1
        """
        commands = diff
        requests = self.get_create_vxlans_request(commands, have)

        if len(requests) == 0:
            commands = []

        if commands:
            commands = update_states(commands, "merged")

        return commands, requests

    def _state_deleted(self, want, have, diff):
        """ The command generator when state is deleted

        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """

        requests = []
        is_delete_all = False
        # if want is none, then delete all the vxlans
        if not want or len(have) == 0:
            commands = have
            is_delete_all = True
        else:
            commands = want

        if is_delete_all:
            requests = self.get_delete_all_vxlan_request(have)
        else:
            requests = self.get_delete_vxlan_request(commands, have)

        if len(requests) == 0:
            commands = []

        if commands:
            commands = update_states(commands, "deleted")

        return commands, requests

    def get_create_vxlans_request(self, configs, have):
        requests = []

        if not configs:
            return requests

        tunnel_requests = self.get_create_tunnel_request(configs, have)
        vlan_map_requests = self.get_create_vlan_map_request(configs, have)
        vrf_map_requests = self.get_create_vrf_map_request(configs, have)

        if tunnel_requests:
            requests.extend(tunnel_requests)
        if vlan_map_requests:
            requests.extend(vlan_map_requests)
        if vrf_map_requests:
            requests.extend(vrf_map_requests)

        return requests

    def get_delete_all_vxlan_request(self, have):
        requests = []

        vrf_map_requests = []
        vlan_map_requests = []
        src_ip_requests = []
        primary_ip_requests = []
        evpn_nvo_requests = []
        tunnel_requests = []

        # Need to delete in reverse order of creation.
        # vrf_map needs to be cleared before vlan_map
        # vlan_map needs to be cleared before tunnel(source-ip)
        for conf in have:
            name = conf['name']
            vlan_map_list = conf.get('vlan_map', [])
            vrf_map_list = conf.get('vrf_map', [])
            src_ip = conf.get('source_ip', None)
            primary_ip = conf.get('primary_ip', None)
            evpn_nvo = conf.get('evpn_nvo', None)

            if vrf_map_list:
                vrf_map_requests.extend(self.get_delete_vrf_map_request(conf, conf, name, vrf_map_list))
            if vlan_map_list:
                vlan_map_requests.extend(self.get_delete_vlan_map_request(conf, conf, name, vlan_map_list))
            if src_ip:
                src_ip_requests.extend(self.get_delete_src_ip_request(conf, conf, name, src_ip))
            if primary_ip:
                primary_ip_requests.extend(self.get_delete_primary_ip_request(conf, conf, name, primary_ip))
            if evpn_nvo:
                evpn_nvo_requests.extend(self.get_delete_evpn_request(conf, conf, evpn_nvo))
            tunnel_requests.extend(self.get_delete_tunnel_request(conf, conf, name))

        if vrf_map_requests:
            requests.extend(vrf_map_requests)
        if vlan_map_requests:
            requests.extend(vlan_map_requests)
        if src_ip_requests:
            requests.extend(src_ip_requests)
        if primary_ip_requests:
            requests.extend(primary_ip_requests)
        if evpn_nvo_requests:
            requests.extend(evpn_nvo_requests)
        if tunnel_requests:
            requests.extend(tunnel_requests)

        return requests

    def get_delete_vxlan_request(self, configs, have):
        requests = []

        if not configs:
            return requests

        vrf_map_requests = []
        vlan_map_requests = []
        src_ip_requests = []
        evpn_nvo_requests = []
        primary_ip_requests = []
        tunnel_requests = []

        # Need to delete in the reverse order of creation.
        # vrf_map needs to be cleared before vlan_map
        # vlan_map needs to be cleared before tunnel(source-ip)
        for conf in configs:

            name = conf['name']
            src_ip = conf.get('source_ip', None)
            evpn_nvo = conf.get('evpn_nvo', None)
            primary_ip = conf.get('primary_ip', None)
            vlan_map_list = conf.get('vlan_map', None)
            vrf_map_list = conf.get('vrf_map', None)

            have_vlan_map_count = 0
            have_vrf_map_count = 0
            matched = next((each_vxlan for each_vxlan in have if each_vxlan['name'] == name), None)
            if matched:
                have_vlan_map = matched.get('vlan_map', [])
                have_vrf_map = matched.get('vrf_map', [])
                if have_vlan_map:
                    have_vlan_map_count = len(have_vlan_map)
                if have_vrf_map:
                    have_vrf_map_count = len(have_vrf_map)

            is_delete_full = False
            if (name and vlan_map_list is None and vrf_map_list is None and
                    src_ip is None and evpn_nvo is None and primary_ip is None):
                is_delete_full = True
                vrf_map_list = matched.get("vrf_map", [])
                vlan_map_list = matched.get("vlan_map", [])

            if vlan_map_list is not None and len(vlan_map_list) == 0 and matched:
                vlan_map_list = matched.get("vlan_map", [])
            if vrf_map_list is not None and len(vrf_map_list) == 0 and matched:
                vrf_map_list = matched.get("vrf_map", [])

            if vrf_map_list:
                temp_vrf_map_requests = self.get_delete_vrf_map_request(conf, matched, name, vrf_map_list)
                if temp_vrf_map_requests:
                    vrf_map_requests.extend(temp_vrf_map_requests)
                    have_vrf_map_count -= len(temp_vrf_map_requests)
            if vlan_map_list:
                temp_vlan_map_requests = self.get_delete_vlan_map_request(conf, matched, name, vlan_map_list)
                if temp_vlan_map_requests:
                    vlan_map_requests.extend(temp_vlan_map_requests)
                    have_vlan_map_count -= len(temp_vlan_map_requests)
            if src_ip:
                src_ip_requests.extend(self.get_delete_src_ip_request(conf, matched, name, src_ip))
            if evpn_nvo:
                evpn_nvo_requests.extend(self.get_delete_evpn_request(conf, matched, evpn_nvo))
            if primary_ip:
                primary_ip_requests.extend(self.get_delete_primary_ip_request(conf, matched, name, primary_ip))
            if is_delete_full:
                tunnel_requests.extend(self.get_delete_tunnel_request(conf, matched, name))

        if vrf_map_requests:
            requests.extend(vrf_map_requests)
        if vlan_map_requests:
            requests.extend(vlan_map_requests)
        if src_ip_requests:
            requests.extend(src_ip_requests)
        if evpn_nvo_requests:
            requests.extend(evpn_nvo_requests)
        if primary_ip_requests:
            requests.extend(primary_ip_requests)
        if tunnel_requests:
            requests.extend(tunnel_requests)

        return requests

    def get_create_evpn_request(self, conf):
        # Create URL and payload
        url = "data/sonic-vxlan:sonic-vxlan/EVPN_NVO/EVPN_NVO_LIST"
        payload = self.build_create_evpn_payload(conf)
        request = {"path": url, "method": PATCH, "data": payload}

        return request

    def get_create_tunnel_request(self, configs, have):
        # Create URL and payload
        requests = []
        url = "data/sonic-vxlan:sonic-vxlan/VXLAN_TUNNEL"
        for conf in configs:
            payload = self.build_create_tunnel_payload(conf)
            request = {"path": url, "method": PATCH, "data": payload}
            requests.append(request)
            if conf.get('evpn_nvo', None):
                requests.append(self.get_create_evpn_request(conf))

        return requests

    def build_create_evpn_payload(self, conf):

        evpn_nvo_list = [{'name': conf['evpn_nvo'], 'source_vtep': conf['name']}]
        evpn_dict = {'sonic-vxlan:EVPN_NVO_LIST': evpn_nvo_list}

        return evpn_dict

    def build_create_tunnel_payload(self, conf):
        payload_url = dict()

        vtep_ip_dict = dict()
        vtep_ip_dict['name'] = conf['name']
        if conf.get('source_ip', None):
            vtep_ip_dict['src_ip'] = conf['source_ip']
        if conf.get('primary_ip', None):
            vtep_ip_dict['primary_ip'] = conf['primary_ip']

        payload_url['sonic-vxlan:VXLAN_TUNNEL'] = {'VXLAN_TUNNEL_LIST': [vtep_ip_dict]}

        return payload_url

    def get_create_vlan_map_request(self, configs, have):
        # Create URL and payload
        requests = []
        for conf in configs:
            new_vlan_map_list = conf.get('vlan_map', [])
            if new_vlan_map_list:
                for each_vlan_map in new_vlan_map_list:
                    name = conf['name']
                    vlan = each_vlan_map.get('vlan')
                    vni = each_vlan_map.get('vni')
                    matched = next((each_vxlan for each_vxlan in have if each_vxlan['name'] == name), None)

                    is_change_needed = True
                    if matched:
                        matched_vlan_map_list = matched.get('vlan_map', [])
                        if matched_vlan_map_list:
                            matched_vlan_map = next((e_vlan_map for e_vlan_map in matched_vlan_map_list if e_vlan_map['vni'] == vni), None)
                            if matched_vlan_map:
                                if matched_vlan_map['vlan'] == vlan:
                                    is_change_needed = False

                    if is_change_needed:
                        map_name = "map_{0}_Vlan{1}".format(vni, vlan)
                        payload = self.build_create_vlan_map_payload(conf, each_vlan_map)
                        url = "data/sonic-vxlan:sonic-vxlan/VXLAN_TUNNEL_MAP"
                        request = {"path": url, "method": PATCH, "data": payload}
                        requests.append(request)

        return requests

    def build_create_vlan_map_payload(self, conf, vlan_map):
        payload_url = dict()

        vlan_map_dict = dict()
        vlan_map_dict['name'] = conf['name']
        vlan_map_dict['mapname'] = "map_{vni}_Vlan{vlan}".format(vni=vlan_map['vni'], vlan=vlan_map['vlan'])
        vlan_map_dict['vlan'] = "Vlan{vlan}".format(vlan=vlan_map['vlan'])
        vlan_map_dict['vni'] = vlan_map['vni']

        payload_url['sonic-vxlan:VXLAN_TUNNEL_MAP'] = {'VXLAN_TUNNEL_MAP_LIST': [vlan_map_dict]}

        return payload_url

    def get_create_vrf_map_request(self, configs, have):
        # Create URL and payload
        requests = []
        for conf in configs:
            new_vrf_map_list = conf.get('vrf_map', [])
            if new_vrf_map_list:
                for each_vrf_map in new_vrf_map_list:
                    name = conf['name']
                    vrf = each_vrf_map.get('vrf')
                    vni = each_vrf_map.get('vni')
                    matched = next((each_vxlan for each_vxlan in have if each_vxlan['name'] == name), None)

                    is_change_needed = True
                    if matched:
                        matched_vrf_map_list = matched.get('vrf_map', [])
                        if matched_vrf_map_list:
                            matched_vrf_map = next((e_vrf_map for e_vrf_map in matched_vrf_map_list if e_vrf_map['vni'] == vni), None)
                            if matched_vrf_map:
                                if matched_vrf_map['vrf'] == vrf:
                                    is_change_needed = False

                    if is_change_needed:
                        payload = self.build_create_vrf_map_payload(conf, each_vrf_map)
                        url = "data/sonic-vrf:sonic-vrf/VRF/VRF_LIST={vrf}/vni".format(vrf=vrf)
                        request = {"path": url, "method": PATCH, "data": payload}
                        requests.append(request)

        return requests

    def build_create_vrf_map_payload(self, conf, vrf_map):

        payload_url = dict({"sonic-vrf:vni": vrf_map['vni']})
        return payload_url

    def get_delete_evpn_request(self, conf, matched, del_evpn_nvo):
        # Create URL and payload
        requests = []

        url = "data/sonic-vxlan:sonic-vxlan/EVPN_NVO/EVPN_NVO_LIST={evpn_nvo}"

        is_change_needed = False
        if matched:
            matched_evpn_nvo = matched.get('evpn_nvo', None)
            if matched_evpn_nvo and matched_evpn_nvo == del_evpn_nvo:
                is_change_needed = True

        if is_change_needed:
            request = {"path": url.format(evpn_nvo=conf['evpn_nvo']), "method": DELETE}
            requests.append(request)

        return requests

    def get_delete_tunnel_request(self, conf, matched, name):
        # Create URL and payload
        requests = []

        url = "data/sonic-vxlan:sonic-vxlan/VXLAN_TUNNEL/VXLAN_TUNNEL_LIST={name}".format(name=name)
        requests.append({"path": url, "method": DELETE})

        return requests

    def get_delete_src_ip_request(self, conf, matched, name, del_source_ip):
        # Create URL and payload
        requests = []

        url = "data/sonic-vxlan:sonic-vxlan/VXLAN_TUNNEL/VXLAN_TUNNEL_LIST={name}/src_ip"

        is_change_needed = False
        if matched:
            matched_source_ip = matched.get('source_ip', None)
            if matched_source_ip and matched_source_ip == del_source_ip:
                is_change_needed = True

        if is_change_needed:
            request = {"path": url.format(name=name), "method": DELETE}
            requests.append(request)

        return requests

    def get_delete_primary_ip_request(self, conf, matched, name, del_primary_ip):
        # Create URL and payload
        requests = []

        url = "data/sonic-vxlan:sonic-vxlan/VXLAN_TUNNEL/VXLAN_TUNNEL_LIST={name}/primary_ip"

        is_change_needed = False
        if matched:
            matched_primary_ip = matched.get('primary_ip', None)
            if matched_primary_ip and matched_primary_ip == del_primary_ip:
                is_change_needed = True

        if is_change_needed:
            request = {"path": url.format(name=name), "method": DELETE}
            requests.append(request)

        return requests

    def get_delete_vlan_map_request(self, conf, matched, name, del_vlan_map_list):
        # Create URL and payload
        requests = []

        for each_vlan_map in del_vlan_map_list:
            vlan = each_vlan_map.get('vlan')
            vni = each_vlan_map.get('vni')

            is_change_needed = False
            if matched:
                matched_vlan_map_list = matched.get('vlan_map', None)
                if matched_vlan_map_list:
                    matched_vlan_map = next((e_vlan_map for e_vlan_map in matched_vlan_map_list if e_vlan_map['vni'] == vni), None)
                    if matched_vlan_map:
                        if matched_vlan_map['vlan'] == vlan:
                            is_change_needed = True

            if is_change_needed:
                map_name = "map_{0}_Vlan{1}".format(vni, vlan)
                url = "data/sonic-vxlan:sonic-vxlan/VXLAN_TUNNEL_MAP/VXLAN_TUNNEL_MAP_LIST={name},{map_name}".format(name=name, map_name=map_name)
                request = {"path": url, "method": DELETE}
                requests.append(request)

        return requests

    def get_delete_vrf_map_request(self, conf, matched, name, del_vrf_map_list):
        # Create URL and payload
        requests = []

        for each_vrf_map in del_vrf_map_list:
            vrf = each_vrf_map.get('vrf')
            vni = each_vrf_map.get('vni')

            is_change_needed = False
            if matched:
                matched_vrf_map_list = matched.get('vrf_map', None)
                if matched_vrf_map_list:
                    matched_vrf_map = next((e_vrf_map for e_vrf_map in matched_vrf_map_list if e_vrf_map['vni'] == vni), None)
                    if matched_vrf_map:
                        if matched_vrf_map['vrf'] == vrf:
                            is_change_needed = True

            if is_change_needed:
                url = "data/sonic-vrf:sonic-vrf/VRF/VRF_LIST={vrf}/vni".format(vrf=vrf)
                request = {"path": url, "method": DELETE}
                requests.append(request)

        return requests

    def sort_lists_in_config(self, config):
        if config:
            config.sort(key=self.get_name)
            for cfg in config:
                if 'vlan_map' in cfg and cfg['vlan_map']:
                    cfg['vlan_map'].sort(key=self.get_vni)
                if 'vrf_map' in cfg and cfg['vrf_map']:
                    cfg['vrf_map'].sort(key=self.get_vni)

    def get_name(self, name):
        return name.get('name')

    def get_vni(self, vni):
        return vni.get('vni')

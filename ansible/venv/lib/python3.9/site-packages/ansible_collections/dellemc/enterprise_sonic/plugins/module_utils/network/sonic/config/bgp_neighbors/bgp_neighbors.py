#
# -*- coding: utf-8 -*-
# Copyright 2019 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_bgp_neighbors class
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
    remove_matching_defaults
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.bgp_utils import (
    validate_bgps,
    normalize_neighbors_interface_name,
    get_ip_afi_cfg_payload,
    get_prefix_limit_payload
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import to_request
from ansible.module_utils.connection import ConnectionError

from copy import deepcopy

PATCH = 'patch'
DELETE = 'delete'

TEST_KEYS = [
    {'config': {'vrf_name': '', 'bgp_as': ''}},
    {'neighbors': {'neighbor': ''}},
    {'peer_group': {'name': ''}},
    {'afis': {'afi': '', 'safi': ''}},
]

default_entries = [
    [
        {'name': 'peer_group'},
        {'name': 'timers'},
        {'name': 'keepalive', 'default': 60}
    ],
    [
        {'name': 'peer_group'},
        {'name': 'timers'},
        {'name': 'holdtime', 'default': 180}
    ],
    [
        {'name': 'peer_group'},
        {'name': 'timers'},
        {'name': 'connect_retry', 'default': 30}
    ],
    [
        {'name': 'peer_group'},
        {'name': 'advertisement_interval', 'default': 30}
    ],
    [
        {'name': 'peer_group'},
        {'name': 'auth_pwd'},
        {'name': 'encrypted', 'default': False}
    ],
    [
        {'name': 'peer_group'},
        {'name': 'ebgp_multihop'},
        {'name': 'enabled', 'default': False}
    ],
    [
        {'name': 'peer_group'},
        {'name': 'passive', 'default': False}
    ],
    [
        {'name': 'peer_group'},
        {'name': 'address_family'},
        {'name': 'afis'},
        {'name': 'ip_afi'},
        {'name': 'send_default_route', 'default': False}
    ],
    [
        {'name': 'peer_group'},
        {'name': 'address_family'},
        {'name': 'afis'},
        {'name': 'activate', 'default': False}
    ],
    [
        {'name': 'peer_group'},
        {'name': 'address_family'},
        {'name': 'afis'},
        {'name': 'prefix_limit'},
        {'name': 'prevent_teardown', 'default': False}
    ],
    [
        {'name': 'neighbors'},
        {'name': 'timers'},
        {'name': 'keepalive', 'default': 60}
    ],
    [
        {'name': 'neighbors'},
        {'name': 'timers'},
        {'name': 'holdtime', 'default': 180}
    ],
    [
        {'name': 'neighbors'},
        {'name': 'timers'},
        {'name': 'connect_retry', 'default': 30}
    ],
    [
        {'name': 'neighbors'},
        {'name': 'advertisement_interval', 'default': 30}
    ],
    [
        {'name': 'neighbors'},
        {'name': 'auth_pwd'},
        {'name': 'encrypted', 'default': False}
    ],
    [
        {'name': 'neighbors'},
        {'name': 'ebgp_multihop'},
        {'name': 'enabled', 'default': False}
    ],
    [
        {'name': 'neighbors'},
        {'name': 'passive', 'default': False}
    ],
]


class Bgp_neighbors(ConfigBase):
    """
    The sonic_bgp_neighbors class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'bgp_neighbors',
    ]

    network_instance_path = '/data/openconfig-network-instance:network-instances/network-instance'
    protocol_bgp_path = 'protocols/protocol=BGP,bgp/bgp'
    neighbor_path = 'neighbors/neighbor'

    def __init__(self, module):
        super(Bgp_neighbors, self).__init__(module)

    def get_bgp_neighbors_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        bgp_facts = facts['ansible_network_resources'].get('bgp_neighbors')
        if not bgp_facts:
            bgp_facts = []
        return bgp_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()
        existing_bgp_facts = self.get_bgp_neighbors_facts()
        commands, requests = self.set_config(existing_bgp_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_bgp_facts = self.get_bgp_neighbors_facts()

        result['before'] = existing_bgp_facts
        if result['changed']:
            result['after'] = changed_bgp_facts

        result['warnings'] = warnings
        return result

    def set_config(self, existing_bgp_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        normalize_neighbors_interface_name(want, self._module)
        have = existing_bgp_facts
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
            commands, requests = self._state_deleted(want, have, diff)
        elif state == 'merged':
            commands, requests = self._state_merged(want, have, diff)
        return commands, requests

    def _state_merged(self, want, have, diff):
        """ The command generator when state is merged

        :param want: the additive configuration as a dictionary
        :param have: the current configuration as a dictionary
        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = []
        requests = []
        commands = diff
        validate_bgps(self._module, commands, have)
        requests = self.get_modify_bgp_requests(commands, have)
        if commands and len(requests) > 0:
            commands = update_states(commands, "merged")
        else:
            commands = []
        return commands, requests

    def _state_deleted(self, want, have, diff):
        """ The command generator when state is deleted

        :param want: the objects from which the configuration should be removed
        :param have: the current configuration as a dictionary
        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        is_delete_all = False
        if not want:
            is_delete_all = True
        if is_delete_all:
            commands = have
            new_have = have
        else:
            new_have = deepcopy(have)
            for default_entry in default_entries:
                remove_matching_defaults(new_have, default_entry)
            d_diff = get_diff(want, new_have, TEST_KEYS, is_skeleton=True)
            delete_diff = get_diff(want, d_diff, TEST_KEYS, is_skeleton=True)
            commands = delete_diff
        requests = self.get_delete_bgp_neighbor_requests(commands, new_have, want, is_delete_all)

        if commands and len(requests) > 0:
            commands = update_states(commands, "deleted")
        else:
            commands = []
        return commands, requests

    def build_bgp_peer_groups_payload(self, cmd, have, bgp_as, vrf_name):
        requests = []
        bgp_peer_group_list = []
        for peer_group in cmd:
            if peer_group:
                bgp_peer_group = {}
                peer_group_cfg = {}
                tmp_bfd = {}
                tmp_ebgp = {}
                tmp_timers = {}
                tmp_capability = {}
                tmp_remote = {}
                tmp_transport = {}
                afi = []
                if peer_group.get('name', None) is not None:
                    peer_group_cfg.update({'peer-group-name': peer_group['name']})
                    bgp_peer_group.update({'peer-group-name': peer_group['name']})
                if peer_group.get('bfd', None) is not None:
                    if peer_group['bfd'].get('enabled', None) is not None:
                        tmp_bfd.update({'enabled': peer_group['bfd']['enabled']})
                    if peer_group['bfd'].get('check_failure', None) is not None:
                        tmp_bfd.update({'check-control-plane-failure': peer_group['bfd']['check_failure']})
                    if peer_group['bfd'].get('profile', None) is not None:
                        tmp_bfd.update({'bfd-profile': peer_group['bfd']['profile']})
                if peer_group.get('auth_pwd', None) is not None:
                    if (peer_group['auth_pwd'].get('pwd', None) is not None and
                            peer_group['auth_pwd'].get('encrypted', None) is not None):
                        bgp_peer_group.update({'auth-password': {'config': {'password': peer_group['auth_pwd']['pwd'],
                                                                            'encrypted': peer_group['auth_pwd']['encrypted']}}})
                if peer_group.get('ebgp_multihop', None) is not None:
                    if peer_group['ebgp_multihop'].get('enabled', None) is not None:
                        tmp_ebgp.update({'enabled': peer_group['ebgp_multihop']['enabled']})
                    if peer_group['ebgp_multihop'].get('multihop_ttl', None) is not None:
                        tmp_ebgp.update({'multihop-ttl': peer_group['ebgp_multihop']['multihop_ttl']})
                if peer_group.get('timers', None) is not None:
                    if peer_group['timers'].get('holdtime', None) is not None:
                        tmp_timers.update({'hold-time': peer_group['timers']['holdtime']})
                    if peer_group['timers'].get('keepalive', None) is not None:
                        tmp_timers.update({'keepalive-interval': peer_group['timers']['keepalive']})
                    if peer_group['timers'].get('connect_retry', None) is not None:
                        tmp_timers.update({'connect-retry': peer_group['timers']['connect_retry']})
                if peer_group.get('capability', None) is not None:
                    if peer_group['capability'].get('dynamic', None) is not None:
                        tmp_capability.update({'capability-dynamic': peer_group['capability']['dynamic']})
                    if peer_group['capability'].get('extended_nexthop', None) is not None:
                        tmp_capability.update({'capability-extended-nexthop': peer_group['capability']['extended_nexthop']})
                if peer_group.get('pg_description', None) is not None:
                    peer_group_cfg.update({'description': peer_group['pg_description']})
                if peer_group.get('disable_connected_check', None) is not None:
                    peer_group_cfg.update({'disable-ebgp-connected-route-check': peer_group['disable_connected_check']})
                if peer_group.get('dont_negotiate_capability', None) is not None:
                    peer_group_cfg.update({'dont-negotiate-capability': peer_group['dont_negotiate_capability']})
                if peer_group.get('enforce_first_as', None) is not None:
                    peer_group_cfg.update({'enforce-first-as': peer_group['enforce_first_as']})
                if peer_group.get('enforce_multihop', None) is not None:
                    peer_group_cfg.update({'enforce-multihop': peer_group['enforce_multihop']})
                if peer_group.get('override_capability', None) is not None:
                    peer_group_cfg.update({'override-capability': peer_group['override_capability']})
                if peer_group.get('shutdown_msg', None) is not None:
                    peer_group_cfg.update({'shutdown-message': peer_group['shutdown_msg']})
                if peer_group.get('solo', None) is not None:
                    peer_group_cfg.update({'solo-peer': peer_group['solo']})
                if peer_group.get('strict_capability_match', None) is not None:
                    peer_group_cfg.update({'strict-capability-match': peer_group['strict_capability_match']})
                if peer_group.get('ttl_security', None) is not None:
                    peer_group_cfg.update({'ttl-security-hops': peer_group['ttl_security']})
                if peer_group.get('local_as', None) is not None:
                    if peer_group['local_as'].get('as', None) is not None:
                        peer_group_cfg.update({'local-as': peer_group['local_as']['as']})
                    if peer_group['local_as'].get('no_prepend', None) is not None:
                        peer_group_cfg.update({'local-as-no-prepend': peer_group['local_as']['no_prepend']})
                    if peer_group['local_as'].get('replace_as', None) is not None:
                        peer_group_cfg.update({'local-as-replace-as': peer_group['local_as']['replace_as']})
                if peer_group.get('local_address', None) is not None:
                    tmp_transport.update({'local-address': peer_group['local_address']})
                if peer_group.get('passive', None) is not None:
                    tmp_transport.update({'passive-mode': peer_group['passive']})
                if peer_group.get('advertisement_interval', None) is not None:
                    tmp_timers.update({'minimum-advertisement-interval': peer_group['advertisement_interval']})
                if peer_group.get('remote_as', None) is not None:
                    have_nei = self.find_pg(have, bgp_as, vrf_name, peer_group)
                    if peer_group['remote_as'].get('peer_as', None) is not None:
                        if have_nei:
                            if have_nei.get("remote_as", None) is not None:
                                if have_nei["remote_as"].get("peer_type", None) is not None:
                                    del_nei = {}
                                    del_nei.update({'name': have_nei['name']})
                                    del_nei.update({'remote_as': have_nei['remote_as']})
                                    requests.extend(self.delete_specific_peergroup_param_request(vrf_name, del_nei))
                        tmp_remote.update({'peer-as': peer_group['remote_as']['peer_as']})
                    if peer_group['remote_as'].get('peer_type', None) is not None:
                        if have_nei:
                            if have_nei.get("remote_as", None) is not None:
                                if have_nei["remote_as"].get("peer_as", None) is not None:
                                    del_nei = {}
                                    del_nei.update({'name': have_nei['name']})
                                    del_nei.update({'remote_as': have_nei['remote_as']})
                                    requests.extend(self.delete_specific_peergroup_param_request(vrf_name, del_nei))
                        tmp_remote.update({'peer-type': peer_group['remote_as']['peer_type'].upper()})
                if peer_group.get('address_family', None) is not None:
                    if peer_group['address_family'].get('afis', None) is not None:
                        for each in peer_group['address_family']['afis']:
                            samp = {}
                            afi_safi_cfg = {}
                            pfx_lmt_cfg = {}
                            pfx_lst_cfg = {}
                            ip_dict = {}
                            if each.get('afi', None) is not None and each.get('safi', None) is not None:
                                afi_safi = each['afi'].upper() + "_" + each['safi'].upper()
                                if afi_safi is not None:
                                    afi_safi_name = 'openconfig-bgp-types:' + afi_safi
                                if afi_safi_name is not None:
                                    samp.update({'afi-safi-name': afi_safi_name})
                                    samp.update({'config': {'afi-safi-name': afi_safi_name}})
                            if each.get('prefix_limit', None) is not None:
                                pfx_lmt_cfg = get_prefix_limit_payload(each['prefix_limit'])
                            if pfx_lmt_cfg and afi_safi == 'L2VPN_EVPN':
                                samp.update({'l2vpn-evpn': {'prefix-limit': {'config': pfx_lmt_cfg}}})
                            else:
                                if each.get('ip_afi', None) is not None:
                                    afi_safi_cfg = get_ip_afi_cfg_payload(each['ip_afi'])
                                    if afi_safi_cfg:
                                        ip_dict.update({'config': afi_safi_cfg})
                                if pfx_lmt_cfg:
                                    ip_dict.update({'prefix-limit': {'config': pfx_lmt_cfg}})
                                if ip_dict and afi_safi == 'IPV4_UNICAST':
                                    samp.update({'ipv4-unicast': ip_dict})
                                elif ip_dict and afi_safi == 'IPV6_UNICAST':
                                    samp.update({'ipv6-unicast': ip_dict})
                            if each.get('activate', None) is not None:
                                enabled = each['activate']
                                if enabled is not None:
                                    samp.update({'config': {'enabled': enabled}})
                            if each.get('allowas_in', None) is not None:
                                have_pg_af = self.find_af(have, bgp_as, vrf_name, peer_group, each['afi'], each['safi'])
                                if each['allowas_in'].get('origin', None) is not None:
                                    if have_pg_af:
                                        if have_pg_af.get('allowas_in', None) is not None:
                                            if have_pg_af['allowas_in'].get('value', None) is not None:
                                                del_nei = {}
                                                del_nei.update({'name': peer_group['name']})
                                                afis_list = []
                                                temp_cfg = {'afi': each['afi'], 'safi': each['safi']}
                                                temp_cfg['allowas_in'] = {'value': have_pg_af['allowas_in']['value']}
                                                afis_list.append(temp_cfg)
                                                del_nei.update({'address_family': {'afis': afis_list}})
                                                requests.extend(self.delete_specific_peergroup_param_request(vrf_name, del_nei))
                                    origin = each['allowas_in']['origin']
                                    samp.update({'allow-own-as': {'config': {'origin': origin, "enabled": bool("true")}}})
                                if each['allowas_in'].get('value', None) is not None:
                                    if have_pg_af:
                                        if have_pg_af.get('allowas_in', None) is not None:
                                            if have_pg_af['allowas_in'].get('origin', None) is not None:
                                                del_nei = {}
                                                del_nei.update({'name': peer_group['name']})
                                                afis_list = []
                                                temp_cfg = {'afi': each['afi'], 'safi': each['safi']}
                                                temp_cfg['allowas_in'] = {'origin': have_pg_af['allowas_in']['origin']}
                                                afis_list.append(temp_cfg)
                                                del_nei.update({'address_family': {'afis': afis_list}})
                                                requests.extend(self.delete_specific_peergroup_param_request(vrf_name, del_nei))
                                    as_count = each['allowas_in']['value']
                                    samp.update({'allow-own-as': {'config': {'as-count': as_count, "enabled": bool("true")}}})
                            if each.get('prefix_list_in', None) is not None:
                                prefix_list_in = each['prefix_list_in']
                                if prefix_list_in is not None:
                                    pfx_lst_cfg.update({'import-policy': prefix_list_in})
                            if each.get('prefix_list_out', None) is not None:
                                prefix_list_out = each['prefix_list_out']
                                if prefix_list_out is not None:
                                    pfx_lst_cfg.update({'export-policy': prefix_list_out})
                            if pfx_lst_cfg:
                                samp.update({'prefix-list': {'config': pfx_lst_cfg}})
                            if samp:
                                afi.append(samp)
                if tmp_bfd:
                    bgp_peer_group.update({'enable-bfd': {'config': tmp_bfd}})
                if tmp_ebgp:
                    bgp_peer_group.update({'ebgp-multihop': {'config': tmp_ebgp}})
                if tmp_timers:
                    bgp_peer_group.update({'timers': {'config': tmp_timers}})
                if tmp_transport:
                    bgp_peer_group.update({'transport': {'config': tmp_transport}})
                if afi and len(afi) > 0:
                    bgp_peer_group.update({'afi-safis': {'afi-safi': afi}})
                if tmp_capability:
                    peer_group_cfg.update(tmp_capability)
                if tmp_remote:
                    peer_group_cfg.update(tmp_remote)
                if peer_group_cfg:
                    bgp_peer_group.update({'config': peer_group_cfg})
                if bgp_peer_group:
                    bgp_peer_group_list.append(bgp_peer_group)
        payload = {'openconfig-network-instance:peer-groups': {'peer-group': bgp_peer_group_list}}
        return payload, requests

    def find_pg(self, have, bgp_as, vrf_name, peergroup):
        mat_dict = next((m_peer for m_peer in have if m_peer['bgp_as'] == bgp_as and m_peer['vrf_name'] == vrf_name), None)
        if mat_dict and mat_dict.get("peer_group", None) is not None:
            mat_pg = next((m for m in mat_dict['peer_group'] if m["name"] == peergroup['name']), None)
            return mat_pg

    def find_af(self, have, bgp_as, vrf_name, peergroup, afi, safi):
        mat_pg = self.find_pg(have, bgp_as, vrf_name, peergroup)
        if mat_pg and mat_pg['address_family'].get('afis', None) is not None:
            mat_af = next((af for af in mat_pg['address_family']['afis'] if af['afi'] == afi and af['safi'] == safi), None)
            return mat_af

    def find_nei(self, have, bgp_as, vrf_name, neighbor):
        mat_dict = next((m_neighbor for m_neighbor in have if m_neighbor['bgp_as'] == bgp_as and m_neighbor['vrf_name'] == vrf_name), None)
        if mat_dict and mat_dict.get("neighbors", None) is not None:
            mat_neighbor = next((m for m in mat_dict['neighbors'] if m["neighbor"] == neighbor['neighbor']), None)
            return mat_neighbor

    def build_bgp_neighbors_payload(self, cmd, have, bgp_as, vrf_name):
        bgp_neighbor_list = []
        requests = []
        for neighbor in cmd:
            if neighbor:
                bgp_neighbor = {}
                neighbor_cfg = {}
                tmp_bfd = {}
                tmp_ebgp = {}
                tmp_timers = {}
                tmp_capability = {}
                tmp_remote = {}
                tmp_transport = {}
                if neighbor.get('bfd', None) is not None:
                    if neighbor['bfd'].get('enabled', None) is not None:
                        tmp_bfd.update({'enabled': neighbor['bfd']['enabled']})
                    if neighbor['bfd'].get('check_failure', None) is not None:
                        tmp_bfd.update({'check-control-plane-failure': neighbor['bfd']['check_failure']})
                    if neighbor['bfd'].get('profile', None) is not None:
                        tmp_bfd.update({'bfd-profile': neighbor['bfd']['profile']})
                if neighbor.get('auth_pwd', None) is not None:
                    if (neighbor['auth_pwd'].get('pwd', None) is not None and
                            neighbor['auth_pwd'].get('encrypted', None) is not None):
                        bgp_neighbor.update({'auth-password': {'config': {'password': neighbor['auth_pwd']['pwd'],
                                                                          'encrypted': neighbor['auth_pwd']['encrypted']}}})
                if neighbor.get('ebgp_multihop', None) is not None:
                    if neighbor['ebgp_multihop'].get('enabled', None) is not None:
                        tmp_ebgp.update({'enabled': neighbor['ebgp_multihop']['enabled']})
                    if neighbor['ebgp_multihop'].get('multihop_ttl', None) is not None:
                        tmp_ebgp.update({'multihop-ttl': neighbor['ebgp_multihop']['multihop_ttl']})
                if neighbor.get('timers', None) is not None:
                    if neighbor['timers'].get('holdtime', None) is not None:
                        tmp_timers.update({'hold-time': neighbor['timers']['holdtime']})
                    if neighbor['timers'].get('keepalive', None) is not None:
                        tmp_timers.update({'keepalive-interval': neighbor['timers']['keepalive']})
                    if neighbor['timers'].get('connect_retry', None) is not None:
                        tmp_timers.update({'connect-retry': neighbor['timers']['connect_retry']})
                if neighbor.get('capability', None) is not None:
                    if neighbor['capability'].get('dynamic', None) is not None:
                        tmp_capability.update({'capability-dynamic': neighbor['capability']['dynamic']})
                    if neighbor['capability'].get('extended_nexthop', None) is not None:
                        tmp_capability.update({'capability-extended-nexthop': neighbor['capability']['extended_nexthop']})
                if neighbor.get('advertisement_interval', None) is not None:
                    tmp_timers.update({'minimum-advertisement-interval': neighbor['advertisement_interval']})
                if neighbor.get('neighbor', None) is not None:
                    bgp_neighbor.update({'neighbor-address': neighbor['neighbor']})
                    neighbor_cfg.update({'neighbor-address': neighbor['neighbor']})
                if neighbor.get('peer_group', None) is not None:
                    neighbor_cfg.update({'peer-group': neighbor['peer_group']})
                if neighbor.get('nbr_description', None) is not None:
                    neighbor_cfg.update({'description': neighbor['nbr_description']})
                if neighbor.get('disable_connected_check', None) is not None:
                    neighbor_cfg.update({'disable-ebgp-connected-route-check': neighbor['disable_connected_check']})
                if neighbor.get('dont_negotiate_capability', None) is not None:
                    neighbor_cfg.update({'dont-negotiate-capability': neighbor['dont_negotiate_capability']})
                if neighbor.get('enforce_first_as', None) is not None:
                    neighbor_cfg.update({'enforce-first-as': neighbor['enforce_first_as']})
                if neighbor.get('enforce_multihop', None) is not None:
                    neighbor_cfg.update({'enforce-multihop': neighbor['enforce_multihop']})
                if neighbor.get('override_capability', None) is not None:
                    neighbor_cfg.update({'override-capability': neighbor['override_capability']})
                if neighbor.get('port', None) is not None:
                    neighbor_cfg.update({'peer-port': neighbor['port']})
                if neighbor.get('shutdown_msg', None) is not None:
                    neighbor_cfg.update({'shutdown-message': neighbor['shutdown_msg']})
                if neighbor.get('solo', None) is not None:
                    neighbor_cfg.update({'solo-peer': neighbor['solo']})
                if neighbor.get('strict_capability_match', None) is not None:
                    neighbor_cfg.update({'strict-capability-match': neighbor['strict_capability_match']})
                if neighbor.get('ttl_security', None) is not None:
                    neighbor_cfg.update({'ttl-security-hops': neighbor['ttl_security']})
                if neighbor.get('v6only', None) is not None:
                    neighbor_cfg.update({'openconfig-bgp-ext:v6only': neighbor['v6only']})
                if neighbor.get('local_as', None) is not None:
                    if neighbor['local_as'].get('as', None) is not None:
                        neighbor_cfg.update({'local-as': neighbor['local_as']['as']})
                    if neighbor['local_as'].get('no_prepend', None) is not None:
                        neighbor_cfg.update({'local-as-no-prepend': neighbor['local_as']['no_prepend']})
                    if neighbor['local_as'].get('replace_as', None) is not None:
                        neighbor_cfg.update({'local-as-replace-as': neighbor['local_as']['replace_as']})
                if neighbor.get('local_address', None) is not None:
                    tmp_transport.update({'local-address': neighbor['local_address']})
                if neighbor.get('passive', None) is not None:
                    tmp_transport.update({'passive-mode': neighbor['passive']})
                if neighbor.get('remote_as', None) is not None:
                    have_nei = self.find_nei(have, bgp_as, vrf_name, neighbor)
                    if neighbor['remote_as'].get('peer_as', None) is not None:
                        if have_nei:
                            if have_nei.get("remote_as", None) is not None:
                                if have_nei["remote_as"].get("peer_type", None) is not None:
                                    del_nei = {}
                                    del_nei.update({'neighbor': have_nei['neighbor']})
                                    del_nei.update({'remote_as': have_nei['remote_as']})
                                    requests.extend(self.delete_specific_param_request(vrf_name, del_nei))
                        tmp_remote.update({'peer-as': neighbor['remote_as']['peer_as']})
                    if neighbor['remote_as'].get('peer_type', None) is not None:
                        if have_nei:
                            if have_nei.get("remote_as", None) is not None:
                                if have_nei["remote_as"].get("peer_as", None) is not None:
                                    del_nei = {}
                                    del_nei.update({'neighbor': have_nei['neighbor']})
                                    del_nei.update({'remote_as': have_nei['remote_as']})
                                    requests.extend(self.delete_specific_param_request(vrf_name, del_nei))
                        tmp_remote.update({'peer-type': neighbor['remote_as']['peer_type'].upper()})
                if tmp_bfd:
                    bgp_neighbor.update({'enable-bfd': {'config': tmp_bfd}})
                if tmp_ebgp:
                    bgp_neighbor.update({'ebgp-multihop': {'config': tmp_ebgp}})
                if tmp_timers:
                    bgp_neighbor.update({'timers': {'config': tmp_timers}})
                if tmp_transport:
                    bgp_neighbor.update({'transport': {'config': tmp_transport}})
                if tmp_capability:
                    neighbor_cfg.update(tmp_capability)
                if tmp_remote:
                    neighbor_cfg.update(tmp_remote)
                if neighbor_cfg:
                    bgp_neighbor.update({'config': neighbor_cfg})
                if bgp_neighbor:
                    bgp_neighbor_list.append(bgp_neighbor)
        payload = {'openconfig-network-instance:neighbors': {'neighbor': bgp_neighbor_list}}
        return payload, requests

    def get_modify_bgp_requests(self, commands, have):
        requests = []
        if not commands:
            return requests

        for cmd in commands:
            edit_path = '%s=%s/%s' % (self.network_instance_path, cmd['vrf_name'], self.protocol_bgp_path)
            if 'peer_group' in cmd and cmd['peer_group']:
                edit_peer_groups_payload, edit_requests = self.build_bgp_peer_groups_payload(cmd['peer_group'], have, cmd['bgp_as'], cmd['vrf_name'])
                edit_peer_groups_path = edit_path + '/peer-groups'
                if edit_requests:
                    requests.extend(edit_requests)
                requests.append({'path': edit_peer_groups_path, 'method': PATCH, 'data': edit_peer_groups_payload})
            if 'neighbors' in cmd and cmd['neighbors']:
                edit_neighbors_payload, edit_requests = self.build_bgp_neighbors_payload(cmd['neighbors'], have, cmd['bgp_as'], cmd['vrf_name'])
                edit_neighbors_path = edit_path + '/neighbors'
                if edit_requests:
                    requests.extend(edit_requests)
                requests.append({'path': edit_neighbors_path, 'method': PATCH, 'data': edit_neighbors_payload})
        return requests

    def get_delete_specific_bgp_peergroup_param_request(self, vrf_name, cmd, want_match):
        requests = []
        want_peer_group = want_match.get('peer_group', None)
        for each in cmd['peer_group']:
            if each:
                name = each.get('name', None)
                remote_as = each.get('remote_as', None)
                timers = each.get('timers', None)
                advertisement_interval = each.get('advertisement_interval', None)
                bfd = each.get('bfd', None)
                capability = each.get('capability', None)
                auth_pwd = each.get('auth_pwd', None)
                pg_description = each.get('pg_description', None)
                disable_connected_check = each.get('disable_connected_check', None)
                dont_negotiate_capability = each.get('dont_negotiate_capability', None)
                ebgp_multihop = each.get('ebgp_multihop', None)
                enforce_first_as = each.get('enforce_first_as', None)
                enforce_multihop = each.get('enforce_multihop', None)
                local_address = each.get('local_address', None)
                local_as = each.get('local_as', None)
                override_capability = each.get('override_capability', None)
                passive = each.get('passive', None)
                shutdown_msg = each.get('shutdown_msg', None)
                solo = each.get('solo', None)
                strict_capability_match = each.get('strict_capability_match', None)
                ttl_security = each.get('ttl_security', None)
                address_family = each.get('address_family', None)
                if (name and not remote_as and not timers and not advertisement_interval and not bfd and not capability and not auth_pwd and not
                        pg_description and disable_connected_check is None and dont_negotiate_capability is None and not ebgp_multihop and
                        enforce_first_as is None and enforce_multihop is None and not local_address and not local_as and override_capability
                        is None and passive is None and not shutdown_msg and solo is None and strict_capability_match is None and not ttl_security and
                        not address_family):
                    want_pg_match = None
                    if want_peer_group:
                        want_pg_match = next((cfg for cfg in want_peer_group if cfg['name'] == name), None)
                    if want_pg_match:
                        keys = ['remote_as', 'timers', 'advertisement_interval', 'bfd', 'capability', 'auth_pwd', 'pg_description',
                                'disable_connected_check', 'dont_negotiate_capability', 'ebgp_multihop', 'enforce_first_as', 'enforce_multihop',
                                'local_address', 'local_as', 'override_capability', 'passive', 'shutdown_msg', 'solo', 'strict_capability_match',
                                'ttl_security', 'address_family']
                        if not any(want_pg_match.get(key, None) for key in keys):
                            requests.append(self.get_delete_vrf_specific_peergroup_request(vrf_name, name))
                else:
                    requests.extend(self.delete_specific_peergroup_param_request(vrf_name, each))
        return requests

    def delete_specific_peergroup_param_request(self, vrf_name, cmd):
        requests = []
        delete_static_path = '%s=%s/%s' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)
        delete_static_path = delete_static_path + '/peer-groups/peer-group=%s' % (cmd['name'])
        if cmd.get('remote_as', None) is not None:
            if cmd['remote_as'].get('peer_as', None) is not None:
                delete_path = delete_static_path + '/config/peer-as'
                requests.append({'path': delete_path, 'method': DELETE})
            elif cmd['remote_as'].get('peer_type', None) is not None:
                delete_path = delete_static_path + '/config/peer-type'
                requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('advertisement_interval', None) is not None:
            delete_path = delete_static_path + '/timers/config/minimum-advertisement-interval'
            requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('timers', None) is not None:
            if cmd['timers'].get('holdtime', None) is not None:
                delete_path = delete_static_path + '/timers/config/hold-time'
                requests.append({'path': delete_path, 'method': DELETE})
            if cmd['timers'].get('keepalive', None) is not None:
                delete_path = delete_static_path + '/timers/config/keepalive-interval'
                requests.append({'path': delete_path, 'method': DELETE})
            if cmd['timers'].get('connect_retry', None) is not None:
                delete_path = delete_static_path + '/timers/config/connect-retry'
                requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('capability', None) is not None:
            if cmd['capability'].get('dynamic', None) is not None:
                delete_path = delete_static_path + '/config/capability-dynamic'
                requests.append({'path': delete_path, 'method': DELETE})
            if cmd['capability'].get('extended_nexthop', None) is not None:
                delete_path = delete_static_path + '/config/capability-extended-nexthop'
                requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('pg_description', None) is not None:
            delete_path = delete_static_path + '/config/description'
            requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('disable_connected_check', None) is not None:
            delete_path = delete_static_path + '/config/disable-ebgp-connected-route-check'
            requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('dont_negotiate_capability', None) is not None:
            delete_path = delete_static_path + '/config/dont-negotiate-capability'
            requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('enforce_first_as', None) is not None:
            delete_path = delete_static_path + '/config/enforce-first-as'
            requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('enforce_multihop', None) is not None:
            delete_path = delete_static_path + '/config/enforce-multihop'
            requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('override_capability', None) is not None:
            delete_path = delete_static_path + '/config/override-capability'
            requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('shutdown_msg', None) is not None:
            delete_path = delete_static_path + '/config/shutdown-message'
            requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('solo', None) is not None:
            delete_path = delete_static_path + '/config/solo-peer'
            requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('strict_capability_match', None) is not None:
            delete_path = delete_static_path + '/config/strict-capability-match'
            requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('ttl_security', None) is not None:
            delete_path = delete_static_path + '/config/ttl-security-hops'
            requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('local_as', None) is not None:
            if cmd['local_as'].get('as', None) is not None:
                delete_path = delete_static_path + '/config/local-as'
                requests.append({'path': delete_path, 'method': DELETE})
            if cmd['local_as'].get('no_prepend', None) is not None:
                delete_path = delete_static_path + '/config/local-as-no-prepend'
                requests.append({'path': delete_path, 'method': DELETE})
            if cmd['local_as'].get('replace_as', None) is not None:
                delete_path = delete_static_path + '/config/local-as-replace-as'
                requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('local_address', None) is not None:
            delete_path = delete_static_path + '/transport/config/local-address'
            requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('passive', None) is not None:
            delete_path = delete_static_path + '/transport/config/passive-mode'
            requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('bfd', None) is not None:
            if cmd['bfd'].get('enabled', None) is not None:
                delete_path = delete_static_path + '/enable-bfd/config/enabled'
                requests.append({'path': delete_path, 'method': DELETE})
            if cmd['bfd'].get('check_failure', None) is not None:
                delete_path = delete_static_path + '/enable-bfd/config/check-control-plane-failure'
                requests.append({'path': delete_path, 'method': DELETE})
            if cmd['bfd'].get('profile', None) is not None:
                delete_path = delete_static_path + '/enable-bfd/config/bfd-profile'
                requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('auth_pwd', None) is not None:
            if cmd['auth_pwd'].get('pwd', None) is not None:
                delete_path = delete_static_path + '/auth-password/config/password'
                requests.append({'path': delete_path, 'method': DELETE})
            if cmd['auth_pwd'].get('encrypted', None) is not None:
                delete_path = delete_static_path + '/auth-password/config/encrypted'
                requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('ebgp_multihop', None) is not None:
            if cmd['ebgp_multihop'].get('enabled', None) is not None:
                delete_path = delete_static_path + '/ebgp-multihop/config/enabled'
                requests.append({'path': delete_path, 'method': DELETE})
            if cmd['ebgp_multihop'].get('multihop_ttl', None) is not None:
                delete_path = delete_static_path + '/ebgp-multihop/config/multihop-ttl'
                requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('address_family', None) is not None:
            if cmd['address_family'].get('afis', None) is None:
                delete_path = delete_static_path + '/afi-safis/afi-safi'
                requests.append({'path': delete_path, 'method': DELETE})
            else:
                for each in cmd['address_family']['afis']:
                    afi = each.get('afi', None)
                    safi = each.get('safi', None)
                    activate = each.get('activate', None)
                    allowas_in = each.get('allowas_in', None)
                    ip_afi = each.get('ip_afi', None)
                    prefix_limit = each.get('prefix_limit', None)
                    prefix_list_in = each.get('prefix_list_in', None)
                    prefix_list_out = each.get('prefix_list_out', None)
                    afi_safi = afi.upper() + '_' + safi.upper()
                    afi_safi_name = 'openconfig-bgp-types:' + afi_safi
                    if (afi and safi and not activate and not allowas_in and not ip_afi and not prefix_limit and not prefix_list_in
                            and not prefix_list_out):
                        delete_path = delete_static_path + '/afi-safis/afi-safi=%s' % (afi_safi_name)
                        requests.append({'path': delete_path, 'method': DELETE})
                    else:
                        if activate:
                            delete_path = delete_static_path + '/afi-safis/afi-safi=%s/config/enabled' % (afi_safi_name)
                            requests.append({'path': delete_path, 'method': DELETE})
                        if allowas_in:
                            if allowas_in.get('origin', None):
                                delete_path = delete_static_path + '/afi-safis/afi-safi=%s/allow-own-as/config/origin' % (afi_safi_name)
                                requests.append({'path': delete_path, 'method': DELETE})
                            if allowas_in.get('value', None):
                                delete_path = delete_static_path + '/afi-safis/afi-safi=%s/allow-own-as/config/as-count' % (afi_safi_name)
                                requests.append({'path': delete_path, 'method': DELETE})
                        if prefix_list_in:
                            delete_path = delete_static_path + '/afi-safis/afi-safi=%s/prefix-list/config/import-policy' % (afi_safi_name)
                            requests.append({'path': delete_path, 'method': DELETE})
                        if prefix_list_out:
                            delete_path = delete_static_path + '/afi-safis/afi-safi=%s/prefix-list/config/export-policy' % (afi_safi_name)
                            requests.append({'path': delete_path, 'method': DELETE})
                        if afi_safi == 'IPV4_UNICAST':
                            if ip_afi:
                                requests.extend(self.delete_ip_afi_requests(ip_afi, afi_safi_name, 'ipv4-unicast', delete_static_path))
                            if prefix_limit:
                                requests.extend(self.delete_prefix_limit_requests(prefix_limit, afi_safi_name, 'ipv4-unicast', delete_static_path))
                        elif afi_safi == 'IPV6_UNICAST':
                            if ip_afi:
                                requests.extend(self.delete_ip_afi_requests(ip_afi, afi_safi_name, 'ipv6-unicast', delete_static_path))
                            if prefix_limit:
                                requests.extend(self.delete_prefix_limit_requests(prefix_limit, afi_safi_name, 'ipv6-unicast', delete_static_path))
                        elif afi_safi == 'L2VPN_EVPN':
                            if prefix_limit:
                                requests.extend(self.delete_prefix_limit_requests(prefix_limit, afi_safi_name, 'l2vpn-evpn', delete_static_path))

        return requests

    def delete_ip_afi_requests(self, ip_afi, afi_safi_name, afi_safi, delete_static_path):
        requests = []
        default_policy_name = ip_afi.get('default_policy_name', None)
        send_default_route = ip_afi.get('send_default_route', None)
        if default_policy_name:
            delete_path = delete_static_path + '/afi-safis/afi-safi=%s/%s/config/default-policy-name' % (afi_safi_name, afi_safi)
            requests.append({'path': delete_path, 'method': DELETE})
        if send_default_route:
            delete_path = delete_static_path + '/afi-safis/afi-safi=%s/%s/config/send_default_route' % (afi_safi_name, afi_safi)
            requests.append({'path': delete_path, 'method': DELETE})

        return requests

    def delete_prefix_limit_requests(self, prefix_limit, afi_safi_name, afi_safi, delete_static_path):
        requests = []
        max_prefixes = prefix_limit.get('max_prefixes', None)
        prevent_teardown = prefix_limit.get('prevent_teardown', None)
        warning_threshold = prefix_limit.get('warning_threshold', None)
        restart_timer = prefix_limit.get('restart_timer', None)
        if max_prefixes:
            delete_path = delete_static_path + '/afi-safis/afi-safi=%s/%s/prefix-limit/config/max-prefixes' % (afi_safi_name, afi_safi)
            requests.append({'path': delete_path, 'method': DELETE})
        if prevent_teardown:
            delete_path = delete_static_path + '/afi-safis/afi-safi=%s/%s/prefix-limit/config/prevent-teardown' % (afi_safi_name, afi_safi)
            requests.append({'path': delete_path, 'method': DELETE})
        if warning_threshold:
            delete_path = delete_static_path + '/afi-safis/afi-safi=%s/%s/prefix-limit/config/warning-threshold-pct' % (afi_safi_name, afi_safi)
            requests.append({'path': delete_path, 'method': DELETE})
        if restart_timer:
            delete_path = delete_static_path + '/afi-safis/afi-safi=%s/%s/prefix-limit/config/restart-timer' % (afi_safi_name, afi_safi)
            requests.append({'path': delete_path, 'method': DELETE})

        return requests

    def get_delete_specific_bgp_param_request(self, vrf_name, cmd, want_match):
        requests = []
        want_neighbors = want_match.get('neighbors', None)
        for each in cmd['neighbors']:
            if each:
                neighbor = each.get('neighbor', None)
                remote_as = each.get('remote_as', None)
                peer_group = each.get('peer_group', None)
                timers = each.get('timers', None)
                advertisement_interval = each.get('advertisement_interval', None)
                bfd = each.get('bfd', None)
                capability = each.get('capability', None)
                auth_pwd = each.get('auth_pwd', None)
                nbr_description = each.get('nbr_description', None)
                disable_connected_check = each.get('disable_connected_check', None)
                dont_negotiate_capability = each.get('dont_negotiate_capability', None)
                ebgp_multihop = each.get('ebgp_multihop', None)
                enforce_first_as = each.get('enforce_first_as', None)
                enforce_multihop = each.get('enforce_multihop', None)
                local_address = each.get('local_address', None)
                local_as = each.get('local_as', None)
                override_capability = each.get('override_capability', None)
                passive = each.get('passive', None)
                port = each.get('port', None)
                shutdown_msg = each.get('shutdown_msg', None)
                solo = each.get('solo', None)
                strict_capability_match = each.get('strict_capability_match', None)
                ttl_security = each.get('ttl_security', None)
                v6only = each.get('v6only', None)
                if (neighbor and not remote_as and not peer_group and not timers and not advertisement_interval and not bfd and not capability and not
                        auth_pwd and not nbr_description and disable_connected_check is None and dont_negotiate_capability is None and not
                        ebgp_multihop and enforce_first_as is None and enforce_multihop is None and not local_address and not local_as and
                        override_capability is None and passive is None and not port and not shutdown_msg and solo is None and strict_capability_match
                        is None and not ttl_security and v6only is None):
                    want_nei_match = None
                    if want_neighbors:
                        want_nei_match = next(cfg for cfg in want_neighbors if cfg['neighbor'] == neighbor)
                    if want_nei_match:
                        keys = ['remote_as', 'peer_group', 'timers', 'advertisement_interval', 'bfd', 'capability', 'auth_pwd', 'nbr_description',
                                'disable_connected_check', 'dont_negotiate_capability', 'ebgp_multihop', 'enforce_first_as', 'enforce_multihop',
                                'local_address', 'local_as', 'override_capability', 'passive', 'port', 'shutdown_msg', 'solo',
                                'strict_capability_match', 'ttl_security', 'v6only']
                        if not any(want_nei_match.get(key, None) for key in keys):
                            requests.append(self.delete_neighbor_whole_request(vrf_name, neighbor))
                else:
                    requests.extend(self.delete_specific_param_request(vrf_name, each))
        return requests

    def delete_neighbor_whole_request(self, vrf_name, neighbor):
        requests = []
        url = '%s=%s/%s/%s=%s/' % (self.network_instance_path, vrf_name, self.protocol_bgp_path, self.neighbor_path, neighbor)
        return ({'path': url, 'method': DELETE})

    def delete_specific_param_request(self, vrf_name, cmd):
        requests = []
        delete_static_path = '%s=%s/%s' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)
        delete_static_path = delete_static_path + '/neighbors/neighbor=%s' % (cmd['neighbor'])
        if cmd.get('remote_as', None) is not None:
            if cmd['remote_as'].get('peer_as', None) is not None:
                delete_path = delete_static_path + '/config/peer-as'
                requests.append({'path': delete_path, 'method': DELETE})
            elif cmd['remote_as'].get('peer_type', None) is not None:
                delete_path = delete_static_path + '/config/peer-type'
                requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('peer_group', None) is not None:
            delete_path = delete_static_path + '/config/peer-group'
            requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('nbr_description', None) is not None:
            delete_path = delete_static_path + '/config/description'
            requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('disable_connected_check', None) is not None:
            delete_path = delete_static_path + '/config/disable-ebgp-connected-route-check'
            requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('dont_negotiate_capability', None) is not None:
            delete_path = delete_static_path + '/config/dont-negotiate-capability'
            requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('enforce_first_as', None) is not None:
            delete_path = delete_static_path + '/config/enforce-first-as'
            requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('enforce_multihop', None) is not None:
            delete_path = delete_static_path + '/config/enforce-multihop'
            requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('override_capability', None) is not None:
            delete_path = delete_static_path + '/config/override-capability'
            requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('port', None) is not None:
            delete_path = delete_static_path + '/config/peer-port'
            requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('shutdown_msg', None) is not None:
            delete_path = delete_static_path + '/config/shutdown-message'
            requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('solo', None) is not None:
            delete_path = delete_static_path + '/config/solo-peer'
            requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('strict_capability_match', None) is not None:
            delete_path = delete_static_path + '/config/strict-capability-match'
            requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('ttl_security', None) is not None:
            delete_path = delete_static_path + '/config/ttl-security-hops'
            requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('v6only', None) is not None:
            delete_path = delete_static_path + '/config/openconfig-bgp-ext:v6only'
            requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('local_as', None) is not None:
            if cmd['local_as'].get('as', None) is not None:
                delete_path = delete_static_path + '/config/local-as'
                requests.append({'path': delete_path, 'method': DELETE})
            if cmd['local_as'].get('no_prepend', None) is not None:
                delete_path = delete_static_path + '/config/local-as-no-prepend'
                requests.append({'path': delete_path, 'method': DELETE})
            if cmd['local_as'].get('replace_as', None) is not None:
                delete_path = delete_static_path + '/config/local-as-replace-as'
                requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('local_address', None) is not None:
            delete_path = delete_static_path + '/transport/config/local-address'
            requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('passive', None) is not None:
            delete_path = delete_static_path + '/transport/config/passive-mode'
            requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('advertisement_interval', None) is not None:
            delete_path = delete_static_path + '/timers/config/minimum-advertisement-interval'
            requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('timers', None) is not None:
            if cmd['timers'].get('holdtime', None) is not None:
                delete_path = delete_static_path + '/timers/config/hold-time'
                requests.append({'path': delete_path, 'method': DELETE})
            if cmd['timers'].get('keepalive', None) is not None:
                delete_path = delete_static_path + '/timers/config/keepalive-interval'
                requests.append({'path': delete_path, 'method': DELETE})
            if cmd['timers'].get('connect_retry', None) is not None:
                delete_path = delete_static_path + '/timers/config/connect-retry'
                requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('capability', None) is not None:
            if cmd['capability'].get('dynamic', None) is not None:
                delete_path = delete_static_path + '/config/capability-dynamic'
                requests.append({'path': delete_path, 'method': DELETE})
            if cmd['capability'].get('extended_nexthop', None) is not None:
                delete_path = delete_static_path + '/config/capability-extended-nexthop'
                requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('bfd', None) is not None:
            if cmd['bfd'].get('enabled', None) is not None:
                delete_path = delete_static_path + '/enable-bfd/config/enabled'
                requests.append({'path': delete_path, 'method': DELETE})
            if cmd['bfd'].get('check_failure', None) is not None:
                delete_path = delete_static_path + '/enable-bfd/config/check-control-plane-failure'
                requests.append({'path': delete_path, 'method': DELETE})
            if cmd['bfd'].get('profile', None) is not None:
                delete_path = delete_static_path + '/enable-bfd/config/bfd-profile'
                requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('auth_pwd', None) is not None:
            if cmd['auth_pwd'].get('pwd', None) is not None:
                delete_path = delete_static_path + '/auth-password/config/password'
                requests.append({'path': delete_path, 'method': DELETE})
            if cmd['auth_pwd'].get('encrypted', None) is not None:
                delete_path = delete_static_path + '/auth-password/config/encrypted'
                requests.append({'path': delete_path, 'method': DELETE})
        if cmd.get('ebgp_multihop', None) is not None:
            if cmd['ebgp_multihop'].get('enabled', None) is not None:
                delete_path = delete_static_path + '/ebgp-multihop/config/enabled'
                requests.append({'path': delete_path, 'method': DELETE})
            if cmd['ebgp_multihop'].get('multihop_ttl', None) is not None:
                delete_path = delete_static_path + '/ebgp-multihop/config/multihop-ttl'
                requests.append({'path': delete_path, 'method': DELETE})

        return requests

    def get_delete_vrf_specific_neighbor_request(self, vrf_name, have):
        requests = []
        for each in have:
            if each.get('neighbor', None):
                requests.append(self.delete_neighbor_whole_request(vrf_name, each['neighbor']))
        return requests

    def get_delete_vrf_specific_peergroup_request(self, vrf_name, peergroup_name):
        requests = []
        delete_neighbor_path = '%s=%s/%s/peer-groups/peer-group=%s' % (self.network_instance_path, vrf_name, self.protocol_bgp_path, peergroup_name)
        return ({'path': delete_neighbor_path, 'method': DELETE})

    def get_delete_all_bgp_neighbor_requests(self, commands):
        requests = []
        for cmd in commands:
            if cmd.get('neighbors', None):
                requests.extend(self.get_delete_vrf_specific_neighbor_request(cmd['vrf_name'], cmd['neighbors']))
            if 'peer_group' in cmd and cmd['peer_group']:
                for each in cmd['peer_group']:
                    requests.append(self.get_delete_vrf_specific_peergroup_request(cmd['vrf_name'], each['name']))
        return requests

    def get_delete_bgp_neighbor_requests(self, commands, have, want, is_delete_all):
        requests = []
        if is_delete_all:
            requests = self.get_delete_all_bgp_neighbor_requests(commands)
        else:
            for cmd in commands:
                vrf_name = cmd['vrf_name']
                as_val = cmd['bgp_as']
                neighbors = cmd.get('neighbors', None)
                peer_group = cmd.get('peer_group', None)
                want_match = next((cfg for cfg in want if vrf_name == cfg['vrf_name'] and as_val == cfg['bgp_as']), None)
                want_neighbors = want_match.get('neighbors', None)
                want_peer_group = want_match.get('peer_group', None)
                if neighbors is None and peer_group is None and want_neighbors is None and want_peer_group is None:
                    new_cmd = {}
                    for each in have:
                        if vrf_name == each['vrf_name'] and as_val == each['bgp_as']:
                            new_neighbors = []
                            new_pg = []
                            if each.get('neighbors', None):
                                new_neighbors = [{'neighbor': i['neighbor']} for i in each.get('neighbors', None)]
                            if each.get('peer_group', None):
                                new_pg = [{'name': i['name']} for i in each.get('peer_group', None)]
                            if new_neighbors:
                                new_cmd['neighbors'] = new_neighbors
                                requests.extend(self.get_delete_vrf_specific_neighbor_request(vrf_name, new_cmd['neighbors']))
                            if new_pg:
                                new_cmd['name'] = new_pg
                                for each in new_cmd['name']:
                                    requests.append(self.get_delete_vrf_specific_peergroup_request(vrf_name, each['name']))
                            break
                else:
                    if neighbors:
                        requests.extend(self.get_delete_specific_bgp_param_request(vrf_name, cmd, want_match))
                    if peer_group:
                        requests.extend(self.get_delete_specific_bgp_peergroup_param_request(vrf_name, cmd, want_match))
        return requests

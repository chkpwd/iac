#
# -*- coding: utf-8 -*-
# Copyright 2021 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The arg spec for the sonic facts module.
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


class FactsArgs(object):  # pylint: disable=R0903

    """ The arg spec for the sonic facts module
    """

    def __init__(self, **kwargs):
        pass

    choices = [
        'all',
        'vlans',
        'interfaces',
        'l2_interfaces',
        'l3_interfaces',
        'lag_interfaces',
        'bgp',
        'bgp_af',
        'bgp_neighbors',
        'bgp_neighbors_af',
        'bgp_as_paths',
        'bgp_communities',
        'bgp_ext_communities',
        'mclag',
        'prefix_lists',
        'vlan_mapping',
        'vrfs',
        'vxlans',
        'users',
        'system',
        'port_breakout',
        'aaa',
        'tacacs_server',
        'radius_server',
        'static_routes',
        'ntp',
        'logging',
        'ip_neighbor',
        'port_group',
        'dhcp_relay',
        'acl_interfaces',
        'l2_acls',
        'l3_acls',
        'lldp_global',
        'mac',
        'bfd',
        'copp',
        'route_maps'
    ]

    argument_spec = {
        'gather_subset': dict(default=['!config'], type='list', elements='str'),
        'gather_network_resources': dict(choices=choices, type='list', elements='str'),
    }

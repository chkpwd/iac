#
# -*- coding: utf-8 -*-
# Copyright 2020 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic l3_interfaces fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from copy import deepcopy

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.l3_interfaces.l3_interfaces import L3_interfacesArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible.module_utils.connection import ConnectionError


class L3_interfacesFacts(object):
    """ The sonic l3_interfaces fact class
    """

    loop_backs = ","

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = L3_interfacesArgs.argument_spec
        spec = deepcopy(self.argument_spec)
        if subspec:
            if options:
                facts_argument_spec = spec[subspec][options]
            else:
                facts_argument_spec = spec[subspec]
        else:
            facts_argument_spec = spec

        self.generated_spec = utils.generate_dict(facts_argument_spec)

    def get_l3_interfaces(self):
        url = "data/openconfig-interfaces:interfaces/interface"
        method = "GET"
        request = [{"path": url, "method": method}]

        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

        l3_lists = []
        if "openconfig-interfaces:interface" in response[0][1]:
            l3_lists = response[0][1].get("openconfig-interfaces:interface", [])

        l3_configs = []
        for l3 in l3_lists:
            l3_dict = dict()
            l3_name = l3["name"]
            if l3_name == "eth0":
                continue

            l3_dict['name'] = l3_name

            ip = None
            anycast_addr = list()
            if l3.get('openconfig-vlan:routed-vlan'):
                ip = l3['openconfig-vlan:routed-vlan']
                if ip.get('openconfig-if-ip:ipv4', None) and ip['openconfig-if-ip:ipv4'].get('openconfig-interfaces-ext:sag-ipv4', None):
                    if ip['openconfig-if-ip:ipv4']['openconfig-interfaces-ext:sag-ipv4'].get('config', None):
                        if ip['openconfig-if-ip:ipv4']['openconfig-interfaces-ext:sag-ipv4']['config'].get('static-anycast-gateway', None):
                            anycast_addr = ip['openconfig-if-ip:ipv4']['openconfig-interfaces-ext:sag-ipv4']['config']['static-anycast-gateway']
            else:
                ip = l3.get('subinterfaces', {}).get('subinterface', [{}])[0]

            l3_dict['ipv4'] = dict()
            l3_ipv4 = list()
            if anycast_addr:
                l3_dict['ipv4']['anycast_addresses'] = anycast_addr
            elif 'openconfig-if-ip:ipv4' in ip and 'addresses' in ip['openconfig-if-ip:ipv4'] and 'address' in ip['openconfig-if-ip:ipv4']['addresses']:
                for ipv4 in ip['openconfig-if-ip:ipv4']['addresses']['address']:
                    if ipv4.get('config') and ipv4.get('config').get('ip'):
                        temp = dict()
                        temp['address'] = str(ipv4['config']['ip']) + '/' + str(ipv4['config']['prefix-length'])
                        temp['secondary'] = ipv4['config']['secondary']
                        l3_ipv4.append(temp)
                if l3_ipv4:
                    l3_dict['ipv4']['addresses'] = l3_ipv4

            l3_dict['ipv6'] = dict()
            l3_ipv6 = list()
            if 'openconfig-if-ip:ipv6' in ip:
                if 'addresses' in ip['openconfig-if-ip:ipv6'] and 'address' in ip['openconfig-if-ip:ipv6']['addresses']:
                    for ipv6 in ip['openconfig-if-ip:ipv6']['addresses']['address']:
                        if ipv6.get('config') and ipv6.get('config').get('ip'):
                            temp = dict()
                            temp['address'] = str(ipv6['config']['ip']) + '/' + str(ipv6['config']['prefix-length'])
                            l3_ipv6.append(temp)
                    if l3_ipv6:
                        l3_dict['ipv6']['addresses'] = l3_ipv6
                if 'config' in ip['openconfig-if-ip:ipv6'] and 'enabled' in ip['openconfig-if-ip:ipv6']['config']:
                    l3_dict['ipv6']['enabled'] = ip['openconfig-if-ip:ipv6']['config']['enabled']

            l3_configs.append(l3_dict)
        return l3_configs

    def populate_facts(self, connection, ansible_facts, data=None):
        """ Populate the facts for l3_interfaces
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if connection:  # just for linting purposes, remove
            pass
        if not data:
            resources = self.get_l3_interfaces()
        objs = []
        for resource in resources:
            if resource:
                obj = self.render_config(self.generated_spec, resource)
                obj = self.transform_config(obj)
                if obj:
                    objs.append(obj)

        ansible_facts['ansible_network_resources'].pop('l3_interfaces', None)
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['l3_interfaces'] = params['config']

        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def render_config(self, spec, conf):
        """
        Render config as dictionary structure and delete keys
          from spec for null values

        :param spec: The facts tree, generated from the argspec
        :param conf: The configuration
        :rtype: dictionary
        :returns: The generated config
        """
        return conf

    def transform_config(self, conf):
        exist_cfg = conf
        trans_cfg = None

        is_loop_back = False
        name = exist_cfg['name']
        if name.startswith('Loopback'):
            is_loop_back = True
            pos = name.find('|')
            if pos > 0:
                name = name[0:pos]

        if not (is_loop_back and self.is_loop_back_already_esist(name)) and (name != "eth0"):
            trans_cfg = dict()
            trans_cfg['name'] = name
            if is_loop_back:
                self.update_loop_backs(name)
            trans_cfg['ipv4'] = exist_cfg.get('ipv4', {})
            trans_cfg['ipv6'] = exist_cfg.get('ipv6', {})

        return trans_cfg

    def reset_loop_backs(self):
        self.loop_backs = ","

    def update_loop_backs(self, loop_back):
        self.loop_backs += "{Loopback},".format(Loopback=loop_back)

    def is_loop_back_already_esist(self, loop_back):
        return (",{0},".format(loop_back) in self.loop_backs)

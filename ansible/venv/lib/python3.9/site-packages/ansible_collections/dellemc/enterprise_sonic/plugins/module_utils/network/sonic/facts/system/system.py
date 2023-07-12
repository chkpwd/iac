#
# -*- coding: utf-8 -*-
# Copyright 2021 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic system fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.system.system import SystemArgs

GET = "get"


class SystemFacts(object):
    """ The sonic system fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = SystemArgs.argument_spec
        spec = deepcopy(self.argument_spec)
        if subspec:
            if options:
                facts_argument_spec = spec[subspec][options]
            else:
                facts_argument_spec = spec[subspec]
        else:
            facts_argument_spec = spec

        self.generated_spec = utils.generate_dict(facts_argument_spec)

    def get_system(self):
        """Get system hostname available in chassis"""
        request = [{"path": "data/openconfig-system:system/config", "method": GET}]
        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)
        if ('openconfig-system:config' in response[0][1]):
            data = response[0][1]['openconfig-system:config']
        else:
            data = {}
        return data

    def get_naming(self):
        """Get interface_naming type available in chassis"""
        request = [{"path": "data/sonic-device-metadata:sonic-device-metadata/DEVICE_METADATA/DEVICE_METADATA_LIST=localhost", "method": GET}]
        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)
        if ('sonic-device-metadata:DEVICE_METADATA_LIST' in response[0][1]):
            intf_data = response[0][1]['sonic-device-metadata:DEVICE_METADATA_LIST']
            if 'intf_naming_mode' in intf_data[0]:
                data = intf_data[0]
            else:
                data = {}
        return data

    def get_anycast_addr(self):
        """Get system anycast address available in chassis"""
        request = [{"path": "data/sonic-sag:sonic-sag/SAG_GLOBAL/SAG_GLOBAL_LIST/", "method": GET}]
        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)
        if ('sonic-sag:SAG_GLOBAL_LIST' in response[0][1]):
            data = response[0][1]['sonic-sag:SAG_GLOBAL_LIST'][0]
        else:
            data = {}
        return data

    def populate_facts(self, connection, ansible_facts, data=None):
        """ Populate the facts for system
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if not data:
            data = self.get_system()
        intf_naming = self.get_naming()
        if intf_naming:
            data.update(intf_naming)
        anycast_addr = self.get_anycast_addr()
        if anycast_addr:
            data.update(anycast_addr)
        objs = []
        objs = self.render_config(self.generated_spec, data)
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['system'] = params['config']
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
        config = self.parse_sonic_system(spec, conf)
        return config

    def parse_sonic_system(self, spec, conf):
        config = deepcopy(spec)
        if conf:
            if ('hostname' in conf) and (conf['hostname']):
                config['hostname'] = conf['hostname']
            if ('intf_naming_mode' in conf) and (conf['intf_naming_mode']):
                config['interface_naming'] = conf['intf_naming_mode']
            if ('IPv4' in conf) and (conf['IPv4'] == "enable"):
                config['anycast_address']['ipv4'] = True
            if ('IPv4' in conf) and (conf['IPv4'] == "disable"):
                config['anycast_address']['ipv4'] = False
            if ('IPv6' in conf) and (conf['IPv6'] == "enable"):
                config['anycast_address']['ipv6'] = True
            if ('IPv6' in conf) and (conf['IPv6'] == "disable"):
                config['anycast_address']['ipv6'] = False
            if ('gwmac' in conf) and (conf['gwmac']):
                config['anycast_address']['mac_address'] = conf['gwmac']
        return utils.remove_empties(config)

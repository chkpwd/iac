#
# -*- coding: utf-8 -*-
# Copyright 2023 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic aaa fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.aaa.aaa import AaaArgs

GET = "get"


class AaaFacts(object):
    """ The sonic aaa fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = AaaArgs.argument_spec
        spec = deepcopy(self.argument_spec)
        if subspec:
            if options:
                facts_argument_spec = spec[subspec][options]
            else:
                facts_argument_spec = spec[subspec]
        else:
            facts_argument_spec = spec

        self.generated_spec = utils.generate_dict(facts_argument_spec)

    def get_aaa(self):
        """Get aaa details available in chassis"""
        request = [{"path": "data/openconfig-system:system/aaa", "method": GET}]
        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)
        data = {}
        if ('openconfig-system:aaa' in response[0][1]):
            if ('authentication' in response[0][1]['openconfig-system:aaa']):
                if ('config' in response[0][1]['openconfig-system:aaa']['authentication']):
                    data = response[0][1]['openconfig-system:aaa']['authentication']['config']
        return data

    def populate_facts(self, connection, ansible_facts, data=None):
        """ Populate the facts for aaa
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if not data:
            data = self.get_aaa()
        objs = []
        objs = self.render_config(self.generated_spec, data)
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['aaa'] = params['config']

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
        config = self.parse_sonic_aaa(spec, conf)
        return config

    def parse_sonic_aaa(self, spec, conf):
        config = deepcopy(spec)
        if conf:
            temp = {}
            if ('authentication-method' in conf) and (conf['authentication-method']):
                if 'local' in conf['authentication-method']:
                    temp['local'] = True
                choices = ['tacacs+', 'ldap', 'radius']
                for i, word in enumerate(conf['authentication-method']):
                    if word in choices:
                        temp['group'] = conf['authentication-method'][i]
            if ('failthrough' in conf):
                temp['fail_through'] = conf['failthrough']
            if temp:
                config['authentication']['data'] = temp
        return utils.remove_empties(config)

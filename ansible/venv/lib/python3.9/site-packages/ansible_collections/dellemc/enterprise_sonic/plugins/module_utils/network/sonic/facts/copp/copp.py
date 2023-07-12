#
# -*- coding: utf-8 -*-
# Copyright 2023 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic copp fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.copp.copp import CoppArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)


class CoppFacts(object):
    """ The sonic copp fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = CoppArgs.argument_spec
        spec = deepcopy(self.argument_spec)
        if subspec:
            if options:
                facts_argument_spec = spec[subspec][options]
            else:
                facts_argument_spec = spec[subspec]
        else:
            facts_argument_spec = spec

        self.generated_spec = utils.generate_dict(facts_argument_spec)

    def populate_facts(self, connection, ansible_facts, data=None):
        """ Populate the facts for bfd
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        objs = []

        if not data:
            copp_cfg = self.get_copp_config(self._module)
            data = self.update_copp_groups(copp_cfg)
        objs = self.render_config(self.generated_spec, data)
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['copp'] = params['config']
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

    def update_copp_groups(self, data):
        config_dict = {}
        all_copp_groups = []
        copp_groups = data.get('copp-groups', None)
        if copp_groups:
            copp_group_list = copp_groups.get('copp-group', None)
            if copp_group_list:
                for group in copp_group_list:
                    group_dict = {}
                    copp_name = group['name']
                    config = group['config']
                    trap_priority = config.get('trap-priority', None)
                    trap_action = config.get('trap-action', None)
                    queue = config.get('queue', None)
                    cir = config.get('cir', None)
                    cbs = config.get('cbs', None)

                    if copp_name:
                        group_dict['copp_name'] = copp_name
                    if trap_priority:
                        group_dict['trap_priority'] = trap_priority
                    if trap_action:
                        group_dict['trap_action'] = trap_action
                    if queue:
                        group_dict['queue'] = queue
                    if cir:
                        group_dict['cir'] = cir
                    if cbs:
                        group_dict['cbs'] = cbs
                    if group_dict:
                        all_copp_groups.append(group_dict)

        config_dict['copp_groups'] = all_copp_groups

        return config_dict

    def get_copp_config(self, module):
        copp_cfg = None
        get_copp_path = '/data/openconfig-copp-ext:copp'
        request = {'path': get_copp_path, 'method': 'get'}

        try:
            response = edit_config(module, to_request(module, request))
            if 'openconfig-copp-ext:copp' in response[0][1]:
                copp_cfg = response[0][1].get('openconfig-copp-ext:copp', None)
        except ConnectionError as exc:
            module.fail_json(msg=str(exc), code=exc.code)

        return copp_cfg

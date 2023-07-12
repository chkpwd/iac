#
# -*- coding: utf-8 -*-
# Copyright 2021 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_system class
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
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    update_states,
    send_requests,
    get_diff,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)

PATCH = 'patch'
DELETE = 'delete'


class System(ConfigBase):
    """
    The sonic_system class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'system',
    ]

    def __init__(self, module):
        super(System, self).__init__(module)

    def get_system_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        system_facts = facts['ansible_network_resources'].get('system')
        if not system_facts:
            return []
        return system_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()
        commands = list()

        existing_system_facts = self.get_system_facts()
        commands, requests = self.set_config(existing_system_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                self.edit_config(requests)
            result['changed'] = True
        result['commands'] = commands

        changed_system_facts = self.get_system_facts()

        result['before'] = existing_system_facts
        if result['changed']:
            result['after'] = changed_system_facts

        result['warnings'] = warnings
        return result

    def edit_config(self, requests):
        try:
            response = edit_config(self._module, to_request(self._module, requests))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

    def set_config(self, existing_system_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        have = existing_system_facts
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
            diff = get_diff(want, have)
            commands = self._state_merged(want, have, diff)
        elif state == 'overridden':
            commands = self._state_overridden(want, have)
        elif state == 'replaced':
            commands = self._state_replaced(want, have)

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
            requests = self.get_create_system_request(want, diff)
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
        new_have = self.remove_default_entries(have)
        if not want:
            if have:
                requests = self.get_delete_all_system_request(new_have)
                if len(requests) > 0:
                    commands = update_states(have, "deleted")
        else:
            want = utils.remove_empties(want)
            d_diff = get_diff(want, new_have, is_skeleton=True)
            diff_want = get_diff(want, d_diff, is_skeleton=True)
            if diff_want:
                requests = self.get_delete_all_system_request(diff_want)
                if len(requests) > 0:
                    commands = update_states(diff_want, "deleted")

        return commands, requests

    def _state_replaced(self, want, have):
        """ The command generator when state is replaced

        :param want: the desired configuration as a dictionary
        :param have: the current configuration as a dictionary
        :param diff: the difference between want and have
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        new_want = self.patch_want_with_default(want, ac_address_only=True)
        replaced_config = self.get_replaced_config(have, new_want)
        if replaced_config:
            requests = self.get_delete_all_system_request(replaced_config)
            send_requests(self._module, requests)
            commands = new_want
        else:
            diff = get_diff(new_want, have)
            commands = diff
            if not commands:
                commands = []

        requests = []

        if commands:
            requests = self.get_create_system_request(have, commands)

            if len(requests) > 0:
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
        new_want = self.patch_want_with_default(want)
        if have and have != new_want:
            requests = self.get_delete_all_system_request(have)
            send_requests(self._module, requests)
            have = []

        commands = []
        requests = []

        if not have and new_want:
            commands = new_want
            requests = self.get_create_system_request(have, commands)
            if len(requests) > 0:
                commands = update_states(commands, "overridden")
            else:
                commands = []

        return commands, requests

    def get_create_system_request(self, want, commands):
        requests = []
        host_path = 'data/openconfig-system:system/config'
        method = PATCH
        hostname_payload = self.build_create_hostname_payload(commands)
        if hostname_payload:
            request = {'path': host_path, 'method': method, 'data': hostname_payload}
            requests.append(request)
        name_path = 'data/sonic-device-metadata:sonic-device-metadata/DEVICE_METADATA/DEVICE_METADATA_LIST=localhost/intf_naming_mode'
        name_payload = self.build_create_name_payload(commands)
        if name_payload:
            request = {'path': name_path, 'method': method, 'data': name_payload}
            requests.append(request)
        anycast_path = 'data/sonic-sag:sonic-sag/SAG_GLOBAL/SAG_GLOBAL_LIST/'
        anycast_payload = self.build_create_anycast_payload(commands)
        if anycast_payload:
            request = {'path': anycast_path, 'method': method, 'data': anycast_payload}
            requests.append(request)
        return requests

    def build_create_hostname_payload(self, commands):
        payload = {}
        if "hostname" in commands and commands["hostname"]:
            payload = {"openconfig-system:config": {}}
            payload['openconfig-system:config'].update({"hostname": commands["hostname"]})
        return payload

    def build_create_name_payload(self, commands):
        payload = {}
        if "interface_naming" in commands and commands["interface_naming"]:
            payload.update({'sonic-device-metadata:intf_naming_mode': commands["interface_naming"]})
        return payload

    def build_create_anycast_payload(self, commands):
        payload = {}
        if "anycast_address" in commands and commands["anycast_address"]:
            payload = {"sonic-sag:SAG_GLOBAL_LIST": []}
            temp = {}
            if "ipv4" in commands["anycast_address"] and commands["anycast_address"]["ipv4"]:
                temp.update({'IPv4': "enable"})
            if "ipv4" in commands["anycast_address"] and not commands["anycast_address"]["ipv4"]:
                temp.update({'IPv4': "disable"})
            if "ipv6" in commands["anycast_address"] and commands["anycast_address"]["ipv6"]:
                temp.update({'IPv6': "enable"})
            if "ipv6" in commands["anycast_address"] and not commands["anycast_address"]["ipv6"]:
                temp.update({'IPv6': "disable"})
            if "mac_address" in commands["anycast_address"] and commands["anycast_address"]["mac_address"]:
                temp.update({'gwmac': commands["anycast_address"]["mac_address"]})
            if temp:
                temp.update({"table_distinguisher": "IP"})
                payload["sonic-sag:SAG_GLOBAL_LIST"].append(temp)
        return payload

    def patch_want_with_default(self, want, ac_address_only=False):
        new_want = {}
        if want is None:
            if ac_address_only:
                new_want = {'anycast_address': {'ipv4': True, 'ipv6': True, 'mac_address': None}}
            else:
                new_want = {'hostname': 'sonic', 'interface_naming': 'native',
                            'anycast_address': {'ipv4': True, 'ipv6': True, 'mac_address': None}}
        else:
            new_want = want.copy()
            new_anycast = {}
            anycast = want.get('anycast_address', None)
            if not anycast:
                new_anycast = {'ipv4': True, 'ipv6': True, 'mac_address': None}
            else:
                new_anycast = anycast.copy()
                ipv4 = anycast.get("ipv4", None)
                if ipv4 is None:
                    new_anycast["ipv4"] = True
                ipv6 = anycast.get("ipv6", None)
                if ipv6 is None:
                    new_anycast["ipv6"] = True
                mac = anycast.get("mac_address", None)
                if mac is None:
                    new_anycast["mac_address"] = None
            new_want["anycast_address"] = new_anycast

            if not ac_address_only:
                hostname = want.get('hostname', None)
                if hostname is None:
                    new_want["hostname"] = 'sonic'
                intf_name = want.get('interface_naming', None)
                if intf_name is None:
                    new_want["interface_naming"] = 'native'
        return new_want

    def get_replaced_config(self, have, want):

        replaced_config = dict()

        h_hostname = have.get('hostname', None)
        w_hostname = want.get('hostname', None)
        if (h_hostname != w_hostname) and w_hostname:
            replaced_config = have.copy()
            return replaced_config
        h_intf_name = have.get('interface_naming', None)
        w_intf_name = want.get('interface_naming', None)
        if (h_intf_name != w_intf_name) and w_intf_name:
            replaced_config = have.copy()
            return replaced_config
        h_ac_addr = have.get('anycast_address', None)
        w_ac_addr = want.get('anycast_address', None)
        if (h_ac_addr != w_ac_addr) and w_ac_addr:
            replaced_config['anycast_address'] = h_ac_addr
            return replaced_config
        return replaced_config

    def remove_default_entries(self, data):
        new_data = {}
        if not data:
            return new_data
        else:
            hostname = data.get('hostname', None)
            if hostname != "sonic":
                new_data["hostname"] = hostname
            intf_name = data.get('interface_naming', None)
            if intf_name != "native":
                new_data["interface_naming"] = intf_name
            new_anycast = {}
            anycast = data.get('anycast_address', None)
            if anycast:
                ipv4 = anycast.get("ipv4", None)
                if ipv4 is not True:
                    new_anycast["ipv4"] = ipv4
                ipv6 = anycast.get("ipv6", None)
                if ipv6 is not True:
                    new_anycast["ipv6"] = ipv6
                mac = anycast.get("mac_address", None)
                if mac is not None:
                    new_anycast["mac_address"] = mac
            new_data["anycast_address"] = new_anycast
        return new_data

    def get_delete_all_system_request(self, have):
        requests = []
        if "hostname" in have:
            request = self.get_hostname_delete_request()
            requests.append(request)
        if "interface_naming" in have:
            request = self.get_intfname_delete_request()
            requests.append(request)
        if "anycast_address" in have:
            request = self.get_anycast_delete_request(have["anycast_address"])
            requests.extend(request)
        return requests

    def get_hostname_delete_request(self):
        path = 'data/openconfig-system:system/config/'
        method = PATCH
        payload = {"openconfig-system:config": {}}
        payload['openconfig-system:config'].update({"hostname": "sonic"})
        request = {'path': path, 'method': method, 'data': payload}
        return request

    def get_intfname_delete_request(self):
        path = 'data/sonic-device-metadata:sonic-device-metadata/DEVICE_METADATA/DEVICE_METADATA_LIST=localhost/intf_naming_mode'
        method = DELETE
        request = {'path': path, 'method': method}
        return request

    def get_anycast_delete_request(self, anycast):
        requests = []
        if "ipv4" in anycast:
            path = 'data/sonic-sag:sonic-sag/SAG_GLOBAL/SAG_GLOBAL_LIST=IP/IPv4'
            method = DELETE
            request = {'path': path, 'method': method}
            requests.append(request)
        if "ipv6" in anycast:
            path = 'data/sonic-sag:sonic-sag/SAG_GLOBAL/SAG_GLOBAL_LIST=IP/IPv6'
            method = DELETE
            request = {'path': path, 'method': method}
            requests.append(request)
        if "mac_address" in anycast:
            path = 'data/sonic-sag:sonic-sag/SAG_GLOBAL/SAG_GLOBAL_LIST=IP/gwmac'
            method = DELETE
            request = {'path': path, 'method': method}
            requests.append(request)
        return requests

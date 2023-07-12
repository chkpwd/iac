#
# -*- coding: utf-8 -*-
# Copyright 2020 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_l3_interfaces class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    get_diff,
    update_states,
    normalize_interface_name,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible.module_utils.connection import ConnectionError

TEST_KEYS = [
    {"addresses": {"address": "", "secondary": ""}}
]

DELETE = "DELETE"
PATCH = "PATCH"


class L3_interfaces(ConfigBase):
    """
    The sonic_l3_interfaces class
    """

    gather_subset = [
        '!all',
        '!min'
    ]

    gather_network_resources = [
        'l3_interfaces',
    ]

    def __init__(self, module):
        super(L3_interfaces, self).__init__(module)

    def get_l3_interfaces_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        l3_interfaces_facts = facts['ansible_network_resources'].get('l3_interfaces')
        if not l3_interfaces_facts:
            return []
        return l3_interfaces_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()

        existing_l3_interfaces_facts = self.get_l3_interfaces_facts()
        commands, requests = self.set_config(existing_l3_interfaces_facts)
        if commands:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_l3_interfaces_facts = self.get_l3_interfaces_facts()

        result['before'] = existing_l3_interfaces_facts
        if result['changed']:
            result['after'] = changed_l3_interfaces_facts

        result['warnings'] = warnings
        return result

    def set_config(self, existing_l3_interfaces_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        normalize_interface_name(want, self._module)
        have = existing_l3_interfaces_facts
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
        diff = get_diff(want, have, TEST_KEYS)
        if state == 'overridden':
            commands, requests = self._state_overridden(want, have, diff)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have, diff)
        elif state == 'merged':
            commands, requests = self._state_merged(want, have, diff)
        elif state == 'replaced':
            commands, requests = self._state_replaced(want, have, diff)
        ret_commands = commands
        return ret_commands, requests

    def _state_replaced(self, want, have, diff):
        """ The command generator when state is replaced

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        ret_requests = list()
        commands = list()
        l3_interfaces_to_delete = get_diff(have, want, TEST_KEYS)
        obj = self.get_object(l3_interfaces_to_delete, want)
        diff = get_diff(obj, want, TEST_KEYS)
        if diff:
            delete_l3_interfaces_requests = self.get_delete_all_requests(want)
            ret_requests.extend(delete_l3_interfaces_requests)
            commands.extend(update_states(want, "deleted"))
            l3_interfaces_to_create_requests = self.get_create_l3_interfaces_requests(want, have, want)
            ret_requests.extend(l3_interfaces_to_create_requests)
            commands.extend(update_states(want, "merged"))
        return commands, ret_requests

    def _state_overridden(self, want, have, diff):
        """ The command generator when state is overridden

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        ret_requests = list()
        commands = list()
        interfaces_to_delete = get_diff(have, want, TEST_KEYS)
        if interfaces_to_delete:
            delete_interfaces_requests = self.get_delete_l3_interfaces_requests(want, have)
            ret_requests.extend(delete_interfaces_requests)
            commands.extend(update_states(interfaces_to_delete, "deleted"))

        if diff:
            interfaces_to_create_requests = self.get_create_l3_interfaces_requests(diff, have, want)
            ret_requests.extend(interfaces_to_create_requests)
            commands.extend(update_states(diff, "merged"))

        return commands, ret_requests

    def _state_merged(self, want, have, diff):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        self.validate_primary_ips(want)
        commands = diff
        requests = self.get_create_l3_interfaces_requests(commands, have, want)
        if commands and len(requests) > 0:
            commands = update_states(commands, "merged")
        else:
            commands = []

        return commands, requests

    def _state_deleted(self, want, have, diff):
        """ The command generator when state is deleted

        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        commands = list()
        if not want:
            commands = have
            requests = self.get_delete_all_completely_requests(commands)
        else:
            commands = want
            requests = self.get_delete_l3_interfaces_requests(commands, have)
        if len(requests) == 0:
            commands = []
        if commands:
            commands = update_states(commands, "deleted")
        return commands, requests

    def get_object(self, have, want):
        objects = list()
        names = [i.get('name', None) for i in want]
        for obj in have:
            if 'name' in obj and obj['name'] in names:
                objects.append(obj.copy())
        return objects

    def get_address(self, ip_str, have_obj):
        to_return = list()
        for i in have_obj:
            if i.get(ip_str) and i[ip_str].get('addresses'):
                for ip in i[ip_str]['addresses']:
                    to_return.append(ip['address'])
        return to_return

    def get_delete_l3_interfaces_requests(self, want, have):
        requests = []
        ipv4_addrs_url_all = 'data/openconfig-interfaces:interfaces/interface={intf_name}/{sub_intf_name}/openconfig-if-ip:ipv4/addresses'
        ipv6_addrs_url_all = 'data/openconfig-interfaces:interfaces/interface={intf_name}/{sub_intf_name}/openconfig-if-ip:ipv6/addresses'
        ipv4_anycast_url = 'data/openconfig-interfaces:interfaces/interface={intf_name}/{sub_intf_name}/openconfig-if-ip:ipv4'
        ipv4_anycast_url += '/openconfig-interfaces-ext:sag-ipv4/config/static-anycast-gateway={anycast_ip}'
        ipv4_addr_url = 'data/openconfig-interfaces:interfaces/interface={intf_name}/{sub_intf_name}/openconfig-if-ip:ipv4/addresses/address={address}'
        ipv6_addr_url = 'data/openconfig-interfaces:interfaces/interface={intf_name}/{sub_intf_name}/openconfig-if-ip:ipv6/addresses/address={address}'
        ipv6_enabled_url = 'data/openconfig-interfaces:interfaces/interface={intf_name}/{sub_intf_name}/openconfig-if-ip:ipv6/config/enabled'

        if not want:
            return requests
        for each_l3 in want:
            l3 = each_l3.copy()
            name = l3.pop('name')
            sub_intf = self.get_sub_interface_name(name)
            have_obj = next((e_cfg for e_cfg in have if e_cfg['name'] == name), None)
            if not have_obj:
                continue
            have_ipv4_addrs = list()
            have_ipv4_anycast_addrs = list()
            have_ipv6_addrs = list()
            have_ipv6_enabled = None

            if have_obj.get('ipv4'):
                if 'addresses' in have_obj['ipv4']:
                    have_ipv4_addrs = have_obj['ipv4']['addresses']
                if 'anycast_addresses' in have_obj['ipv4']:
                    have_ipv4_anycast_addrs = have_obj['ipv4']['anycast_addresses']

            have_ipv6_addrs = self.get_address('ipv6', [have_obj])
            if have_obj.get('ipv6') and 'enabled' in have_obj['ipv6']:
                have_ipv6_enabled = have_obj['ipv6']['enabled']

            ipv4 = l3.get('ipv4', None)
            ipv6 = l3.get('ipv6', None)

            ipv4_addrs = None
            ipv6_addrs = None

            is_del_ipv4 = None
            is_del_ipv6 = None
            if name and ipv4 is None and ipv6 is None:
                is_del_ipv4 = True
                is_del_ipv6 = True
            elif ipv4 and not ipv4.get('addresses') and not ipv4.get('anycast_addresses'):
                is_del_ipv4 = True
            elif ipv6 and not ipv6.get('addresses') and ipv6.get('enabled') is None:
                is_del_ipv6 = True

            if is_del_ipv4:
                if have_ipv4_addrs and len(have_ipv4_addrs) != 0:
                    ipv4_addrs_delete_request = {"path": ipv4_addrs_url_all.format(intf_name=name, sub_intf_name=sub_intf), "method": DELETE}
                    requests.append(ipv4_addrs_delete_request)
                if have_ipv4_anycast_addrs and len(have_ipv4_anycast_addrs) != 0:
                    for ip in have_ipv4_anycast_addrs:
                        ip = ip.replace('/', '%2f')
                        anycast_delete_request = {"path": ipv4_anycast_url.format(intf_name=name, sub_intf_name=sub_intf, anycast_ip=ip), "method": DELETE}
                        requests.append(anycast_delete_request)
            else:
                ipv4_addrs = []
                ipv4_anycast_addrs = []
                if l3.get('ipv4'):
                    if l3['ipv4'].get('addresses'):
                        ipv4_addrs = l3['ipv4']['addresses']
                    if l3['ipv4'].get('anycast_addresses'):
                        ipv4_anycast_addrs = l3['ipv4']['anycast_addresses']

                # Store the primary ip at end of the list. So primary ip will be deleted after the secondary ips
                ipv4_del_reqs = []
                if ipv4_addrs:
                    for ip in ipv4_addrs:
                        if have_ipv4_addrs:
                            match_ip = next((addr for addr in have_ipv4_addrs if addr['address'] == ip['address']), None)
                            if match_ip:
                                addr = ip['address'].split('/')[0]
                                del_url = ipv4_addr_url.format(intf_name=name, sub_intf_name=sub_intf, address=addr)
                                if match_ip['secondary']:
                                    del_url += '/config/secondary'
                                    ipv4_del_reqs.insert(0, {"path": del_url, "method": DELETE})
                                else:
                                    ipv4_del_reqs.append({"path": del_url, "method": DELETE})
                            if ipv4_del_reqs:
                                requests.extend(ipv4_del_reqs)

                if ipv4_anycast_addrs:
                    for ip in ipv4_anycast_addrs:
                        if have_ipv4_anycast_addrs and ip in have_ipv4_anycast_addrs:
                            ip = ip.replace('/', '%2f')
                            anycast_delete_request = {"path": ipv4_anycast_url.format(intf_name=name, sub_intf_name=sub_intf, anycast_ip=ip), "method": DELETE}
                            requests.append(anycast_delete_request)

            if is_del_ipv6:
                if have_ipv6_addrs and len(have_ipv6_addrs) != 0:
                    ipv6_addrs_delete_request = {"path": ipv6_addrs_url_all.format(intf_name=name, sub_intf_name=sub_intf), "method": DELETE}
                    requests.append(ipv6_addrs_delete_request)

                if have_ipv6_enabled:
                    ipv6_enabled_delete_request = {"path": ipv6_enabled_url.format(intf_name=name, sub_intf_name=sub_intf), "method": DELETE}
                    requests.append(ipv6_enabled_delete_request)
            else:
                ipv6_addrs = []
                ipv6_enabled = None
                if l3.get('ipv6'):
                    if l3['ipv6'].get('addresses'):
                        ipv6_addrs = l3['ipv6']['addresses']
                    if 'enabled' in l3['ipv6']:
                        ipv6_enabled = l3['ipv6']['enabled']
                if ipv6_addrs:
                    for ip in ipv6_addrs:
                        if have_ipv6_addrs and ip['address'] in have_ipv6_addrs:
                            addr = ip['address'].split('/')[0]
                            request = {"path": ipv6_addr_url.format(intf_name=name, sub_intf_name=sub_intf, address=addr), "method": DELETE}
                            requests.append(request)

                if have_ipv6_enabled and ipv6_enabled is not None:
                    request = {"path": ipv6_enabled_url.format(intf_name=name, sub_intf_name=sub_intf), "method": DELETE}
                    requests.append(request)
        return requests

    def get_delete_all_completely_requests(self, configs):
        delete_requests = list()
        for l3 in configs:
            if l3['ipv4'] or l3['ipv6']:
                delete_requests.append(l3)
        return self.get_delete_all_requests(delete_requests)

    def get_delete_all_requests(self, configs):
        requests = []
        ipv4_addrs_url_all = 'data/openconfig-interfaces:interfaces/interface={intf_name}/{sub_intf_name}/openconfig-if-ip:ipv4/addresses'
        ipv4_anycast_url = 'data/openconfig-interfaces:interfaces/interface={intf_name}/{sub_intf_name}/openconfig-if-ip:ipv4'
        ipv4_anycast_url += '/openconfig-interfaces-ext:sag-ipv4/config/static-anycast-gateway={anycast_ip}'
        ipv6_addrs_url_all = 'data/openconfig-interfaces:interfaces/interface={intf_name}/{sub_intf_name}/openconfig-if-ip:ipv6/addresses'
        ipv6_enabled_url = 'data/openconfig-interfaces:interfaces/interface={intf_name}/{sub_intf_name}/openconfig-if-ip:ipv6/config/enabled'
        for l3 in configs:
            name = l3.get('name')
            ipv4_addrs = []
            ipv4_anycast = []
            if l3.get('ipv4'):
                if l3['ipv4'].get('addresses'):
                    ipv4_addrs = l3['ipv4']['addresses']
                if l3['ipv4'].get('anycast_addresses', None):
                    ipv4_anycast = l3['ipv4']['anycast_addresses']

            ipv6_addrs = []
            ipv6_enabled = None
            if l3.get('ipv6'):
                if l3['ipv6'].get('addresses'):
                    ipv6_addrs = l3['ipv6']['addresses']
                if 'enabled' in l3['ipv6']:
                    ipv6_enabled = l3['ipv6']['enabled']

            sub_intf = self.get_sub_interface_name(name)

            if ipv4_addrs:
                ipv4_addrs_delete_request = {"path": ipv4_addrs_url_all.format(intf_name=name, sub_intf_name=sub_intf), "method": DELETE}
                requests.append(ipv4_addrs_delete_request)
            if ipv4_anycast:
                for ip in ipv4_anycast:
                    ip = ip.replace('/', '%2f')
                    anycast_delete_request = {"path": ipv4_anycast_url.format(intf_name=name, sub_intf_name=sub_intf, anycast_ip=ip), "method": DELETE}
                    requests.append(anycast_delete_request)
            if ipv6_addrs:
                ipv6_addrs_delete_request = {"path": ipv6_addrs_url_all.format(intf_name=name, sub_intf_name=sub_intf), "method": DELETE}
                requests.append(ipv6_addrs_delete_request)
            if ipv6_enabled:
                ipv6_enabled_delete_request = {"path": ipv6_enabled_url.format(intf_name=name, sub_intf_name=sub_intf), "method": DELETE}
                requests.append(ipv6_enabled_delete_request)
        return requests

    def get_create_l3_interfaces_requests(self, configs, have, want):
        requests = []
        if not configs:
            return requests

        ipv4_addrs_url = 'data/openconfig-interfaces:interfaces/interface={intf_name}/{sub_intf_name}/openconfig-if-ip:ipv4/addresses'
        ipv4_anycast_url = 'data/openconfig-interfaces:interfaces/interface={intf_name}/{sub_intf_name}/openconfig-if-ip:ipv4/'
        ipv4_anycast_url += 'openconfig-interfaces-ext:sag-ipv4/config/static-anycast-gateway'
        ipv6_addrs_url = 'data/openconfig-interfaces:interfaces/interface={intf_name}/{sub_intf_name}/openconfig-if-ip:ipv6/addresses'
        ipv6_enabled_url = 'data/openconfig-interfaces:interfaces/interface={intf_name}/{sub_intf_name}/openconfig-if-ip:ipv6/config'

        for l3 in configs:
            l3_interface_name = l3.get('name')
            if l3_interface_name == "eth0":
                continue

            sub_intf = self.get_sub_interface_name(l3_interface_name)

            ipv4_addrs = []
            ipv4_anycast = []
            if l3.get('ipv4'):
                if l3['ipv4'].get('addresses'):
                    ipv4_addrs = l3['ipv4']['addresses']
                if l3['ipv4'].get('anycast_addresses'):
                    ipv4_anycast = l3['ipv4']['anycast_addresses']

            ipv6_addrs = []
            ipv6_enabled = None
            if l3.get('ipv6'):
                if l3['ipv6'].get('addresses'):
                    ipv6_addrs = l3['ipv6']['addresses']
                if 'enabled' in l3['ipv6']:
                    ipv6_enabled = l3['ipv6']['enabled']

            if ipv4_addrs:
                ipv4_addrs_pri_payload = []
                ipv4_addrs_sec_payload = []
                for item in ipv4_addrs:
                    ipv4_addr_mask = item['address'].split('/')
                    ipv4 = ipv4_addr_mask[0]
                    ipv4_mask = ipv4_addr_mask[1]
                    ipv4_secondary = item['secondary']
                    if ipv4_secondary:
                        ipv4_addrs_sec_payload.append(self.build_create_addr_payload(ipv4, ipv4_mask, ipv4_secondary))
                    else:
                        ipv4_addrs_pri_payload.append(self.build_create_addr_payload(ipv4, ipv4_mask, ipv4_secondary))
                if ipv4_addrs_pri_payload:
                    payload = self.build_create_payload(ipv4_addrs_pri_payload)
                    ipv4_addrs_req = {"path": ipv4_addrs_url.format(intf_name=l3_interface_name, sub_intf_name=sub_intf), "method": PATCH, "data": payload}
                    requests.append(ipv4_addrs_req)
                if ipv4_addrs_sec_payload:
                    payload = self.build_create_payload(ipv4_addrs_sec_payload)
                    ipv4_addrs_req = {"path": ipv4_addrs_url.format(intf_name=l3_interface_name, sub_intf_name=sub_intf), "method": PATCH, "data": payload}
                    requests.append(ipv4_addrs_req)

            if ipv4_anycast:
                anycast_payload = {'openconfig-interfaces-ext:static-anycast-gateway': ipv4_anycast}
                anycast_url = ipv4_anycast_url.format(intf_name=l3_interface_name, sub_intf_name=sub_intf)
                requests.append({'path': anycast_url, 'method': PATCH, 'data': anycast_payload})

            if ipv6_addrs:
                ipv6_addrs_payload = []
                for item in ipv6_addrs:
                    ipv6_addr_mask = item['address'].split('/')
                    ipv6 = ipv6_addr_mask[0]
                    ipv6_mask = ipv6_addr_mask[1]
                    ipv6_addrs_payload.append(self.build_create_addr_payload(ipv6, ipv6_mask))
                if ipv6_addrs_payload:
                    payload = self.build_create_payload(ipv6_addrs_payload)
                    ipv6_addrs_req = {"path": ipv6_addrs_url.format(intf_name=l3_interface_name, sub_intf_name=sub_intf), "method": PATCH, "data": payload}
                    requests.append(ipv6_addrs_req)

            if ipv6_enabled is not None:
                payload = self.build_update_ipv6_enabled(ipv6_enabled)
                ipv6_enabled_req = {"path": ipv6_enabled_url.format(intf_name=l3_interface_name, sub_intf_name=sub_intf), "method": PATCH, "data": payload}
                requests.append(ipv6_enabled_req)

        return requests

    def validate_primary_ips(self, want):
        error_intf = {}
        for l3 in want:
            l3_interface_name = l3.get('name')

            ipv4_addrs = []
            if l3.get('ipv4') and l3['ipv4'].get('addresses'):
                ipv4_addrs = l3['ipv4']['addresses']

            if ipv4_addrs:
                ipv4_pri_addrs = [addr['address'] for addr in ipv4_addrs if not addr['secondary']]
                if len(ipv4_pri_addrs) > 1:
                    error_intf[l3_interface_name] = ipv4_pri_addrs

        if error_intf:
            err = "Multiple ipv4 primary ips found! " + str(error_intf)
            self._module.fail_json(msg=str(err), code=300)

    def build_create_payload(self, addrs_payload):
        payload = {'openconfig-if-ip:addresses': {'address': addrs_payload}}
        return payload

    def build_create_addr_payload(self, ip, mask, secondary=None):
        cfg = {'ip': ip, 'prefix-length': float(mask)}
        if secondary:
            cfg['secondary'] = secondary
        addr_payload = {'ip': ip, 'openconfig-if-ip:config': cfg}
        return addr_payload

    def get_sub_interface_name(self, name):
        sub_intf = "subinterfaces/subinterface=0"
        if name.startswith("Vlan"):
            sub_intf = "openconfig-vlan:routed-vlan"
        return sub_intf

    def build_update_ipv6_enabled(self, ipv6_enabled):
        payload = {'config': {'enabled': ipv6_enabled}}
        return payload

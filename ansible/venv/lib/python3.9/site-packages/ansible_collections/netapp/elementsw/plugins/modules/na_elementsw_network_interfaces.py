#!/usr/bin/python
# (c) 2018, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

'''
Element Software Node Network Interfaces - Bond 1G and 10G configuration
'''
from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}


DOCUMENTATION = '''

module: na_elementsw_network_interfaces

short_description: NetApp Element Software Configure Node Network Interfaces
extends_documentation_fragment:
    - netapp.elementsw.netapp.solidfire
version_added: 2.7.0
author: NetApp Ansible Team (@carchi8py) <ng-ansibleteam@netapp.com>
description:
  - Configure Element SW Node Network Interfaces for Bond 1G and 10G IP addresses.
  - This module does not create interfaces, it expects the interfaces to already exists and can only modify them.
  - This module cannot set or modify the method (Loopback, manual, dhcp, static).
  - This module is not idempotent and does not support check_mode.

options:
    method:
        description:
          - deprecated, this option would trigger a 'updated failed' error
        type: str

    ip_address_1g:
        description:
          - deprecated, use bond_1g option.
        type: str

    ip_address_10g:
        description:
          - deprecated, use bond_10g option.
        type: str

    subnet_1g:
        description:
          - deprecated, use bond_1g option.
        type: str

    subnet_10g:
        description:
          - deprecated, use bond_10g option.
        type: str

    gateway_address_1g:
        description:
          - deprecated, use bond_1g option.
        type: str

    gateway_address_10g:
        description:
          - deprecated, use bond_10g option.
        type: str

    mtu_1g:
        description:
          - deprecated, use bond_1g option.
        type: str

    mtu_10g:
        description:
          - deprecated, use bond_10g option.
        type: str

    dns_nameservers:
        description:
          - deprecated, use bond_1g and bond_10g options.
        type: list
        elements: str

    dns_search_domains:
        description:
          - deprecated, use bond_1g and bond_10g options.
        type: list
        elements: str

    bond_mode_1g:
        description:
          - deprecated, use bond_1g option.
        type: str

    bond_mode_10g:
        description:
          - deprecated, use bond_10g option.
        type: str

    lacp_1g:
        description:
          - deprecated, use bond_1g option.
        type: str

    lacp_10g:
        description:
          - deprecated, use bond_10g option.
        type: str

    virtual_network_tag:
        description:
          - deprecated, use bond_1g and bond_10g options.
        type: str

    bond_1g:
      description:
        - settings for the Bond1G interface.
      type: dict
      suboptions:
        address:
          description:
            - IP address for the interface.
          type: str
        netmask:
          description:
            - subnet mask for the interface.
          type: str
        gateway:
          description:
            - IP router network address to send packets out of the local network.
          type: str
        mtu:
          description:
            - The largest packet size (in bytes) that the interface can transmit..
            - Must be greater than or equal to 1500 bytes.
          type: str
        dns_nameservers:
          description:
            - List of addresses for domain name servers.
          type: list
          elements: str
        dns_search:
          description:
            - List of DNS search domains.
          type: list
          elements: str
        bond_mode:
          description:
            - Bonding mode.
          choices: ['ActivePassive', 'ALB', 'LACP']
          type: str
        bond_lacp_rate:
          description:
            - Link Aggregation Control Protocol - useful only if LACP is selected as the Bond Mode.
            - Slow - Packets are transmitted at 30 second intervals.
            - Fast - Packets are transmitted in 1 second intervals.
          choices: ['Fast', 'Slow']
          type: str
        virtual_network_tag:
          description:
            - The virtual network identifier of the interface (VLAN tag).
          type: str

    bond_10g:
      description:
        - settings for the Bond10G interface.
      type: dict
      suboptions:
        address:
          description:
            - IP address for the interface.
          type: str
        netmask:
          description:
            - subnet mask for the interface.
          type: str
        gateway:
          description:
            - IP router network address to send packets out of the local network.
          type: str
        mtu:
          description:
            - The largest packet size (in bytes) that the interface can transmit..
            - Must be greater than or equal to 1500 bytes.
          type: str
        dns_nameservers:
          description:
            - List of addresses for domain name servers.
          type: list
          elements: str
        dns_search:
          description:
            - List of DNS search domains.
          type: list
          elements: str
        bond_mode:
          description:
            - Bonding mode.
          choices: ['ActivePassive', 'ALB', 'LACP']
          type: str
        bond_lacp_rate:
          description:
            - Link Aggregation Control Protocol - useful only if LACP is selected as the Bond Mode.
            - Slow - Packets are transmitted at 30 second intervals.
            - Fast - Packets are transmitted in 1 second intervals.
          choices: ['Fast', 'Slow']
          type: str
        virtual_network_tag:
          description:
            - The virtual network identifier of the interface (VLAN tag).
          type: str

'''

EXAMPLES = """

  - name: Set Node network interfaces configuration for Bond 1G and 10G properties
    tags:
    - elementsw_network_interfaces
    na_elementsw_network_interfaces:
      hostname: "{{ elementsw_hostname }}"
      username: "{{ elementsw_username }}"
      password: "{{ elementsw_password }}"
      bond_1g:
        address: 10.253.168.131
        netmask: 255.255.248.0
        gateway: 10.253.168.1
        mtu: '1500'
        bond_mode: ActivePassive
        dns_nameservers: dns1,dns2
        dns_search: domain1,domain2
      bond_10g:
        address: 10.253.1.202
        netmask: 255.255.255.192
        gateway: 10.253.1.193
        mtu: '9000'
        bond_mode: LACP
        bond_lacp_rate: Fast
        virtual_network_tag: vnet_tag
"""

RETURN = """

msg:
    description: Success message
    returned: success
    type: str

"""
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.elementsw.plugins.module_utils.netapp as netapp_utils

HAS_SF_SDK = netapp_utils.has_sf_sdk()

try:
    from solidfire.models import Network, NetworkConfig
    from solidfire.common import ApiConnectionError as sf_ApiConnectionError, ApiServerError as sf_ApiServerError
    HAS_SF_SDK = True
except ImportError:
    HAS_SF_SDK = False


class ElementSWNetworkInterfaces(object):
    """
    Element Software Network Interfaces - Bond 1G and 10G Network configuration
    """

    def __init__(self):
        self.argument_spec = netapp_utils.ontap_sf_host_argument_spec()
        self.argument_spec.update(dict(
            method=dict(required=False, type='str'),
            ip_address_1g=dict(required=False, type='str'),
            ip_address_10g=dict(required=False, type='str'),
            subnet_1g=dict(required=False, type='str'),
            subnet_10g=dict(required=False, type='str'),
            gateway_address_1g=dict(required=False, type='str'),
            gateway_address_10g=dict(required=False, type='str'),
            mtu_1g=dict(required=False, type='str'),
            mtu_10g=dict(required=False, type='str'),
            dns_nameservers=dict(required=False, type='list', elements='str'),
            dns_search_domains=dict(required=False, type='list', elements='str'),
            bond_mode_1g=dict(required=False, type='str'),
            bond_mode_10g=dict(required=False, type='str'),
            lacp_1g=dict(required=False, type='str'),
            lacp_10g=dict(required=False, type='str'),
            virtual_network_tag=dict(required=False, type='str'),
            bond_1g=dict(required=False, type='dict', options=dict(
                address=dict(required=False, type='str'),
                netmask=dict(required=False, type='str'),
                gateway=dict(required=False, type='str'),
                mtu=dict(required=False, type='str'),
                dns_nameservers=dict(required=False, type='list', elements='str'),
                dns_search=dict(required=False, type='list', elements='str'),
                bond_mode=dict(required=False, type='str', choices=['ActivePassive', 'ALB', 'LACP']),
                bond_lacp_rate=dict(required=False, type='str', choices=['Fast', 'Slow']),
                virtual_network_tag=dict(required=False, type='str'),
            )),
            bond_10g=dict(required=False, type='dict', options=dict(
                address=dict(required=False, type='str'),
                netmask=dict(required=False, type='str'),
                gateway=dict(required=False, type='str'),
                mtu=dict(required=False, type='str'),
                dns_nameservers=dict(required=False, type='list', elements='str'),
                dns_search=dict(required=False, type='list', elements='str'),
                bond_mode=dict(required=False, type='str', choices=['ActivePassive', 'ALB', 'LACP']),
                bond_lacp_rate=dict(required=False, type='str', choices=['Fast', 'Slow']),
                virtual_network_tag=dict(required=False, type='str'),
            )),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False
        )

        input_params = self.module.params
        self.fail_when_deprecated_options_are_set(input_params)

        self.bond1g = input_params['bond_1g']
        self.bond10g = input_params['bond_10g']

        if HAS_SF_SDK is False:
            self.module.fail_json(msg="Unable to import the SolidFire Python SDK")
        # increase time out, as it may take 30 seconds when making a change
        self.sfe = netapp_utils.create_sf_connection(module=self.module, port=442, timeout=90)

    def fail_when_deprecated_options_are_set(self, input_params):
        ''' report an error and exit if any deprecated options is set '''

        dparms_1g = [x for x in ('ip_address_1g', 'subnet_1g', 'gateway_address_1g', 'mtu_1g', 'bond_mode_1g', 'lacp_1g')
                     if input_params[x] is not None]
        dparms_10g = [x for x in ('ip_address_10g', 'subnet_10g', 'gateway_address_10g', 'mtu_10g', 'bond_mode_10g', 'lacp_10g')
                      if input_params[x] is not None]
        dparms_common = [x for x in ('dns_nameservers', 'dns_search_domains', 'virtual_network_tag')
                         if input_params[x] is not None]

        error_msg = ''
        if dparms_1g and dparms_10g:
            error_msg = 'Please use the new bond_1g and bond_10g options to configure the bond interfaces.'
        elif dparms_1g:
            error_msg = 'Please use the new bond_1g option to configure the bond 1G interface.'
        elif dparms_10g:
            error_msg = 'Please use the new bond_10g option to configure the bond 10G interface.'
        elif dparms_common:
            error_msg = 'Please use the new bond_1g or bond_10g options to configure the bond interfaces.'
        if input_params['method']:
            error_msg = 'This module cannot set or change "method".  ' + error_msg
            dparms_common.append('method')
        if error_msg:
            error_msg += '  The following parameters are deprecated and cannot be used: '
            dparms = dparms_1g
            dparms.extend(dparms_10g)
            dparms.extend(dparms_common)
            error_msg += ', '.join(dparms)
            self.module.fail_json(msg=error_msg)

    def set_network_config(self, network_object):
        """
        set network configuration
        """
        try:
            self.sfe.set_network_config(network=network_object)
        except (sf_ApiConnectionError, sf_ApiServerError) as exception_object:
            self.module.fail_json(msg='Error  setting network config for node %s' % (to_native(exception_object)),
                                  exception=traceback.format_exc())

    def set_network_config_object(self, network_params):
        ''' set SolidFire network config object '''
        network_config = dict()
        if network_params is not None:
            for key in network_params:
                if network_params[key] is not None:
                    network_config[key] = network_params[key]
        if network_config:
            return NetworkConfig(**network_config)
        return None

    def set_network_object(self):
        """
        Set Element SW Network object
        :description: set Network object

        :return: Network object
        :rtype: object(Network object)
        """
        bond_1g_network = self.set_network_config_object(self.bond1g)
        bond_10g_network = self.set_network_config_object(self.bond10g)
        network_object = None
        if bond_1g_network is not None or bond_10g_network is not None:
            network_object = Network(bond1_g=bond_1g_network,
                                     bond10_g=bond_10g_network)
        return network_object

    def apply(self):
        """
        Check connection and initialize node with cluster ownership
        """
        changed = False
        result_message = None
        network_object = self.set_network_object()
        if network_object is not None:
            if not self.module.check_mode:
                self.set_network_config(network_object)
            changed = True
        else:
            result_message = "Skipping changes, No change requested"
        self.module.exit_json(changed=changed, msg=result_message)


def main():
    """
    Main function
    """
    elementsw_network_interfaces = ElementSWNetworkInterfaces()
    elementsw_network_interfaces.apply()


if __name__ == '__main__':
    main()

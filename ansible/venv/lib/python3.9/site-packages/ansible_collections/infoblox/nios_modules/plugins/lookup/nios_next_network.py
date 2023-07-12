# Copyright (c) 2018-2019 Red Hat, Inc.
# Copyright (c) 2020 Infoblox, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
name: nios_next_network
short_description: Return the next available network range for a network-container
version_added: "1.0.0"
description:
  - Uses the Infoblox WAPI API to return the next available network addresses for
    a given network CIDR
requirements:
  - infoblox_client

options:
    _terms:
      description: The CIDR network to retrieve the next network from next available network within the specified
                   container.
      required: True
      type: str
    cidr:
      description:
        - The CIDR of the network to retrieve the next network from next available network within the
          specified container. Also, Requested CIDR must be specified and greater than the parent CIDR.
      required: True
      type: str
    num:
      description: The number of network addresses to return from network-container.
      required: false
      default: 1
      type: int
    exclude:
      description: Network addresses returned from network-container excluding list of user's input network range.
      required: false
      default: ''
      type: list
      elements: str
    network_view:
      description: The network view to retrieve the CIDR network from.
      required: false
      default: default
      type: str
'''

EXAMPLES = """
- name: return next available network for network-container 192.168.10.0/24
  ansible.builtin.set_fact:
    networkaddr: "{{ lookup('infoblox.nios_modules.nios_next_network', '192.168.10.0/24', cidr=25,
                        provider={'host': 'nios01', 'username': 'admin', 'password': 'password'}) }}"

- name: return next available network for network-container 192.168.10.0/24 in a non-default network view
  ansible.builtin.set_fact:
    networkaddr: "{{ lookup('infoblox.nios_modules.nios_next_network', '192.168.10.0/24', cidr=25, network_view='ansible'
                        provider={'host': 'nios01', 'username': 'admin', 'password': 'password'}) }}"

- name: return the next 2 available network addresses for network-container 192.168.10.0/24
  ansible.builtin.set_fact:
    networkaddr: "{{ lookup('infoblox.nios_modules.nios_next_network', '192.168.10.0/24', cidr=25, num=2,
                        provider={'host': 'nios01', 'username': 'admin', 'password': 'password'}) }}"

- name: return the available network addresses for network-container 192.168.10.0/24 excluding network range '192.168.10.0/25'
  ansible.builtin.set_fact:
    networkaddr: "{{ lookup('infoblox.nios_modules.nios_next_network', '192.168.10.0/24', cidr=25, exclude=['192.168.10.0/25'],
                        provider={'host': 'nios01', 'username': 'admin', 'password': 'password'}) }}"
"""

RETURN = """
_list:
  description:
    - The list of next network addresses available
  returned: always
  type: list
"""

from ansible.plugins.lookup import LookupBase
from ansible.module_utils._text import to_text
from ansible.errors import AnsibleError
from ..module_utils.api import WapiLookup


class LookupModule(LookupBase):

    def run(self, terms, variables=None, **kwargs):
        try:
            network = terms[0]
        except IndexError:
            raise AnsibleError('missing network argument in the form of A.B.C.D/E')
        try:
            cidr = kwargs.get('cidr', 24)
        except IndexError:
            raise AnsibleError('missing CIDR argument in the form of xx')

        provider = kwargs.pop('provider', {})
        wapi = WapiLookup(provider)
        network_obj = wapi.get_object('networkcontainer', {'network': network})

        if network_obj is None:
            raise AnsibleError('unable to find network-container object %s' % network)
        num = kwargs.get('num', 1)
        exclude_ip = kwargs.get('exclude', [])
        network_view = kwargs.get('network_view', 'default')

        try:
            ref_list = [network['_ref'] for network in network_obj if network['network_view'] == network_view]
            if not ref_list:
                raise AnsibleError('no records found')
            else:
                ref = ref_list[0]
            avail_nets = wapi.call_func('next_available_network', ref, {'cidr': cidr, 'num': num, 'exclude': exclude_ip})
            return [avail_nets['networks']]
        except Exception as exc:
            raise AnsibleError(to_text(exc))

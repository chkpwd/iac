#!/usr/bin/python
#
# Copyright (c) 2018, Yanis Guenane <yanis+ansible@guenane.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


DOCUMENTATION = r'''
---
module: vultr_network_info
short_description: Gather information about the Vultr networks available.
description:
  - Gather information about networks available in Vultr.
version_added: "0.1.0"
author: "Yanis Guenane (@Spredzy)"
extends_documentation_fragment:
- ngine_io.vultr.vultr

'''

EXAMPLES = r'''
- name: Gather Vultr networks information
  ngine_io.vultr.vultr_network_info:
  register: result

- name: Print the gathered information
  debug:
    var: result.vultr_network_info
'''

RETURN = r'''
---
vultr_api:
  description: Response from Vultr API with a few additions/modification
  returned: success
  type: complex
  contains:
    api_account:
      description: Account used in the ini file to select the key
      returned: success
      type: str
      sample: default
    api_timeout:
      description: Timeout used for the API requests
      returned: success
      type: int
      sample: 60
    api_retries:
      description: Amount of max retries for the API requests
      returned: success
      type: int
      sample: 5
    api_retry_max_delay:
      description: Exponential backoff delay in seconds between retries up to this max delay value.
      returned: success
      type: int
      sample: 12
    api_endpoint:
      description: Endpoint used for the API requests
      returned: success
      type: str
      sample: "https://api.vultr.com"
vultr_network_info:
  description: Response from Vultr API
  returned: success
  type: complex
  contains:
    id:
      description: ID of the network
      returned: success
      type: str
      sample: "net5b62c6dc63ef5"
    name:
      description: Name (label) of the network
      returned: success
      type: str
      sample: "mynetwork"
    date_created:
      description: Date when the network was created
      returned: success
      type: str
      sample: "2018-08-02 08:54:52"
    region:
      description: Region the network was deployed into
      returned: success
      type: str
      sample: "Amsterdam"
    v4_subnet:
      description: IPv4 Network address
      returned: success
      type: str
      sample: "192.168.42.0"
    v4_subnet_mask:
      description: Ipv4 Network mask
      returned: success
      type: int
      sample: 24
'''

from ansible.module_utils.basic import AnsibleModule
from ..module_utils.vultr import (
    Vultr,
    vultr_argument_spec,
)


class AnsibleVultrNetworkInfo(Vultr):

    def __init__(self, module):
        super(AnsibleVultrNetworkInfo, self).__init__(module, "vultr_network_info")

        self.returns = {
            'DCID': dict(key='region', transform=self._get_region_name),
            'NETWORKID': dict(key='id'),
            'date_created': dict(),
            'description': dict(key='name'),
            'v4_subnet': dict(),
            'v4_subnet_mask': dict(convert_to='int'),
        }

    def _get_region_name(self, region):
        return self.query_resource_by_key(
            key='DCID',
            value=region,
            resource='regions',
            use_cache=True
        )['name']

    def get_networks(self):
        return self.api_query(path="/v1/network/list")


def parse_network_list(network_list):
    if isinstance(network_list, list):
        return []

    return [network for id, network in network_list.items()]


def main():
    argument_spec = vultr_argument_spec()

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    network_info = AnsibleVultrNetworkInfo(module)
    result = network_info.get_result(parse_network_list(network_info.get_networks()))
    module.exit_json(**result)


if __name__ == '__main__':
    main()

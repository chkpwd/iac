#!/usr/bin/python
#
# Copyright (c) 2018, Yanis Guenane <yanis+ansible@guenane.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


DOCUMENTATION = r'''
---
module: vultr_firewall_group_info
short_description: Gather information about the Vultr firewall groups available.
description:
  - Gather information about firewall groups available in Vultr.
version_added: "0.1.0"
author: "Yanis Guenane (@Spredzy)"
extends_documentation_fragment:
- ngine_io.vultr.vultr

'''

EXAMPLES = r'''
- name: Gather Vultr firewall groups information
  ngine_io.vultr.vultr_firewall_group_info:
  register: result

- name: Print the gathered information
  debug:
    var: result.vultr_firewall_group_info
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
vultr_firewall_group_info:
  description: Response from Vultr API
  returned: success
  type: complex
  contains:
    id:
      description: ID of the firewall group
      returned: success
      type: str
      sample: 1234abcd
    description:
      description: Name of the firewall group
      returned: success
      type: str
      sample: my firewall group
    date_created:
      description: Date the firewall group was created
      returned: success
      type: str
      sample: "2017-08-26 12:47:48"
    date_modified:
      description: Date the firewall group was modified
      returned: success
      type: str
      sample: "2017-08-26 12:47:48"
'''

from ansible.module_utils.basic import AnsibleModule
from ..module_utils.vultr import (
    Vultr,
    vultr_argument_spec,
)


class AnsibleVultrFirewallGroupInfo(Vultr):

    def __init__(self, module):
        super(AnsibleVultrFirewallGroupInfo, self).__init__(module, "vultr_firewall_group_info")

        self.returns = {
            "FIREWALLGROUPID": dict(key='id'),
            "date_created": dict(),
            "date_modified": dict(),
            "description": dict(),
            "instance_count": dict(convert_to='int'),
            "max_rule_count": dict(convert_to='int'),
            "rule_count": dict(convert_to='int')
        }

    def get_firewall_group(self):
        return self.api_query(path="/v1/firewall/group_list")


def parse_fw_group_list(fwgroups_list):
    if not fwgroups_list:
        return []

    return [group for id, group in fwgroups_list.items()]


def main():
    argument_spec = vultr_argument_spec()

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    fw_group_info = AnsibleVultrFirewallGroupInfo(module)
    result = fw_group_info.get_result(parse_fw_group_list(fw_group_info.get_firewall_group()))
    module.exit_json(**result)


if __name__ == '__main__':
    main()

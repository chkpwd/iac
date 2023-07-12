#!/usr/bin/python
#
# Copyright (c) 2018, Yanis Guenane <yanis+ansible@guenane.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


DOCUMENTATION = r'''
---
module: vultr_dns_domain_info
short_description: Gather information about the Vultr DNS domains available.
description:
  - Gather information about DNS domains available in Vultr.
version_added: "0.1.0"
author: "Yanis Guenane (@Spredzy)"
extends_documentation_fragment:
- ngine_io.vultr.vultr

'''

EXAMPLES = r'''
- name: Gather Vultr DNS domains information
  ngine_io.vultr.vultr_dns_domains_info:
  register: result

- name: Print the gathered information
  debug:
    var: result.vultr_dns_domain_info
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
vultr_dns_domain_info:
  description: Response from Vultr API
  returned: success
  type: complex
  contains:
    domain:
      description: Name of the DNS Domain.
      returned: success
      type: str
      sample: example.com
    date_created:
      description: Date the DNS domain was created.
      returned: success
      type: str
      sample: "2017-08-26 12:47:48"
'''

from ansible.module_utils.basic import AnsibleModule
from ..module_utils.vultr import (
    Vultr,
    vultr_argument_spec,
)


class AnsibleVultrDnsDomainInfo(Vultr):

    def __init__(self, module):
        super(AnsibleVultrDnsDomainInfo, self).__init__(module, "vultr_dns_domain_info")

        self.returns = {
            "date_created": dict(),
            "domain": dict(),
        }

    def get_domains(self):
        return self.api_query(path="/v1/dns/list")


def main():
    argument_spec = vultr_argument_spec()

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    domain_info = AnsibleVultrDnsDomainInfo(module)
    result = domain_info.get_result(domain_info.get_domains())
    module.exit_json(**result)


if __name__ == '__main__':
    main()

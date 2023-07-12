#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: active_directory_trusted_domains_info
short_description: Information module for Active Directory Trusted Domains
description:
- Get all Active Directory Trusted Domains.
- This API gets the list of domains that are accessible through the given join.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options:
  id:
    description:
    - Id path parameter.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    active_directory.ActiveDirectory.get_trusted_domains,

  - Paths used are
    put /ers/config/activedirectory/{id}/getTrustedDomains,

"""

EXAMPLES = r"""
- name: Get all Active Directory Trusted Domains
  cisco.ise.active_directory_trusted_domains_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    id: string
  register: result

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "domains": [
        {
          "dnsName": "string",
          "forest": "string",
          "unusableReason": "string"
        }
      ]
    }
"""

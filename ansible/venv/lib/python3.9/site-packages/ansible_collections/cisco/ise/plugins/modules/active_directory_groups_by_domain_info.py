#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: active_directory_groups_by_domain_info
short_description: Information module for Active Directory Groups By Domain
description:
- Get all Active Directory Groups By Domain.
- This API lists the groups of the given domain.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options:
  id:
    description:
    - Id path parameter.
    type: str
  additionalData:
    description: Active Directory Get Groups By Domain Info's additionalData.
    elements: dict
    suboptions:
      name:
        description: Active Directory Get Groups By Domain Info's name.
        type: str
      value:
        description: Active Directory Get Groups By Domain Info's value.
        type: str
    type: list
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    active_directory.ActiveDirectory.get_groups_by_domain,

  - Paths used are
    put /ers/config/activedirectory/{id}/getGroupsByDomain,

"""

EXAMPLES = r"""
- name: Get all Active Directory Groups By Domain
  cisco.ise.active_directory_groups_by_domain_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    id: string
    additionalData:
    - name: domain
      value: Required. The domain whose groups we want to fetch
    - name: filter
      value: Optional. Exact match filter on group's CN
    - name: sidFilter
      value: Optional. Exact match filter on group's SID, optionally specifying the domain
        as prefix. e.g. S-1-5-33-544 and R1.dom/S-1-5-33-544 are legal
    - name: typeFilter
      value: Optional. Can be exactly one of:BUILTIN, DOMAIN LOCAL, GLOBAL, UNIVERSAL
  register: result

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "groups": [
        {
          "groupName": "string",
          "sid": "string",
          "type": "string"
        }
      ]
    }
"""

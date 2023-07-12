#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: active_directory_user_groups_info
short_description: Information module for Active Directory User Groups
description:
- Get all Active Directory User Groups.
- This API allows the client to get groups of which a given user is a member.
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
    description: Active Directory Get User Groups Info's additionalData.
    elements: dict
    suboptions:
      name:
        description: Active Directory Get User Groups Info's name.
        type: str
      value:
        description: Active Directory Get User Groups Info's value.
        type: str
    type: list
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    active_directory.ActiveDirectory.get_user_groups,

  - Paths used are
    put /ers/config/activedirectory/{id}/getUserGroups,

"""

EXAMPLES = r"""
- name: Get all Active Directory User Groups
  cisco.ise.active_directory_user_groups_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    id: string
    additionalData:
    - name: username
      value: Required. The user to get its groups.
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

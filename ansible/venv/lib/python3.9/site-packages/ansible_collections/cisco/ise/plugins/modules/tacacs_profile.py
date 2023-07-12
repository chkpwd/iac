#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: tacacs_profile
short_description: Resource module for TACACS Profile
description:
- Manage operations create, update and delete of the resource TACACS Profile.
- This API creates a TACACS profile.
- This API deletes a TACACS profile.
- This API allows the client to update a TACACS profile.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  description:
    description: TACACS Profile's description.
    type: str
  id:
    description: TACACS Profile's id.
    type: str
  name:
    description: TACACS Profile's name.
    type: str
  sessionAttributes:
    description: Holds list of session attributes. View type for GUI is Shell by default.
    suboptions:
      sessionAttributeList:
        description: TACACS Profile's sessionAttributeList.
        elements: dict
        suboptions:
          name:
            description: TACACS Profile's name.
            type: str
          type:
            description: Allowed values MANDATORY, OPTIONAL.
            type: str
          value:
            description: TACACS Profile's value.
            type: str
        type: list
    type: dict
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    tacacs_profile.TacacsProfile.create_tacacs_profile,
    tacacs_profile.TacacsProfile.delete_tacacs_profile_by_id,
    tacacs_profile.TacacsProfile.update_tacacs_profile_by_id,

  - Paths used are
    post /ers/config/tacacsprofile,
    delete /ers/config/tacacsprofile/{id},
    put /ers/config/tacacsprofile/{id},

"""

EXAMPLES = r"""
- name: Update by id
  cisco.ise.tacacs_profile:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    description: string
    id: string
    name: string
    sessionAttributes:
      sessionAttributeList:
      - name: string
        type: string
        value: string

- name: Delete by id
  cisco.ise.tacacs_profile:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    id: string

- name: Create
  cisco.ise.tacacs_profile:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    description: string
    name: string
    sessionAttributes:
      sessionAttributeList:
      - name: string
        type: string
        value: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "id": "string",
      "name": "string",
      "description": "string",
      "sessionAttributes": {
        "sessionAttributeList": [
          {
            "type": "string",
            "name": "string",
            "value": "string"
          }
        ]
      },
      "link": {
        "rel": "string",
        "href": "string",
        "type": "string"
      }
    }

ise_update_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  version_added: '1.1.0'
  type: dict
  sample: >
    {
      "UpdatedFieldsList": {
        "updatedField": [
          {
            "field": "string",
            "oldValue": "string",
            "newValue": "string"
          }
        ],
        "field": "string",
        "oldValue": "string",
        "newValue": "string"
      }
    }
"""

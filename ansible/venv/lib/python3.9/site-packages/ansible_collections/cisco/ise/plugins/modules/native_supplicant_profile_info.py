#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: native_supplicant_profile_info
short_description: Information module for Native Supplicant Profile
description:
- Get all Native Supplicant Profile.
- Get Native Supplicant Profile by id.
- This API allows the client to get a native supplicant profile by ID.
- This API allows the client to get all the native supplicant profiles.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options:
  id:
    description:
    - Id path parameter.
    type: str
  page:
    description:
    - Page query parameter. Page number.
    type: int
  size:
    description:
    - Size query parameter. Number of objects returned per page.
    type: int
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for NativeSupplicantProfile
  description: Complete reference of the NativeSupplicantProfile API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!nspprofile
notes:
  - SDK Method used are
    native_supplicant_profile.NativeSupplicantProfile.get_native_supplicant_profile_by_id,
    native_supplicant_profile.NativeSupplicantProfile.get_native_supplicant_profile_generator,

  - Paths used are
    get /ers/config/nspprofile,
    get /ers/config/nspprofile/{id},

"""

EXAMPLES = r"""
- name: Get all Native Supplicant Profile
  cisco.ise.native_supplicant_profile_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    page: 1
    size: 20
  register: result

- name: Get Native Supplicant Profile by id
  cisco.ise.native_supplicant_profile_info:
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
      "id": "string",
      "name": "string",
      "description": "string",
      "wirelessProfiles": [
        {
          "ssid": "string",
          "allowedProtocol": "string",
          "certificateTemplateId": "string",
          "actionType": "string",
          "previousSsid": "string"
        }
      ],
      "link": {
        "rel": "string",
        "href": "string",
        "type": "string"
      }
    }

ise_responses:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  version_added: '1.1.0'
  type: list
  elements: dict
  sample: >
    [
      {
        "id": "string",
        "name": "string",
        "description": "string",
        "wirelessProfiles": [
          {
            "ssid": "string",
            "allowedProtocol": "string",
            "certificateTemplateId": "string",
            "actionType": "string",
            "previousSsid": "string"
          }
        ],
        "link": {
          "rel": "string",
          "href": "string",
          "type": "string"
        }
      }
    ]
"""

#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: certificate_profile_info
short_description: Information module for Certificate Profile
description:
- Get all Certificate Profile.
- Get Certificate Profile by id.
- Get Certificate Profile by name.
- This API allows the client to get a certificate profile by ID.
- This API allows the client to get a certificate profile by name.
- This API allows the client to get all the certificate profiles.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options:
  name:
    description:
    - Name path parameter.
    type: str
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
notes:
  - SDK Method used are
    certificate_profile.CertificateProfile.get_certificate_profile_by_id,
    certificate_profile.CertificateProfile.get_certificate_profile_by_name,
    certificate_profile.CertificateProfile.get_certificate_profile_generator,

  - Paths used are
    get /ers/config/certificateprofile,
    get /ers/config/certificateprofile/name/{name},
    get /ers/config/certificateprofile/{id},

"""

EXAMPLES = r"""
- name: Get all Certificate Profile
  cisco.ise.certificate_profile_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    page: 1
    size: 20
  register: result

- name: Get Certificate Profile by id
  cisco.ise.certificate_profile_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    id: string
  register: result

- name: Get Certificate Profile by name
  cisco.ise.certificate_profile_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    name: string
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
      "externalIdentityStoreName": "string",
      "certificateAttributeName": "string",
      "allowedAsUserName": true,
      "matchMode": "string",
      "usernameFrom": "string",
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
        "externalIdentityStoreName": "string",
        "certificateAttributeName": "string",
        "allowedAsUserName": true,
        "matchMode": "string",
        "usernameFrom": "string",
        "link": {
          "rel": "string",
          "href": "string",
          "type": "string"
        }
      }
    ]
"""

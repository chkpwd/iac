#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: certificate_profile
short_description: Resource module for Certificate Profile
description:
- Manage operations create and update of the resource Certificate Profile.
- This API allows the client to create a certificate profile.
- This API allows the client to update a certificate profile.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  allowedAsUserName:
    description: AllowedAsUserName flag.
    type: bool
  certificateAttributeName:
    description: Attribute name of the Certificate Profile - used only when CERTIFICATE
      is chosen in usernameFrom. Allowed values - SUBJECT_COMMON_NAME - SUBJECT_ALTERNATIVE_NAME
      - SUBJECT_SERIAL_NUMBER - SUBJECT - SUBJECT_ALTERNATIVE_NAME_OTHER_NAME - SUBJECT_ALTERNATIVE_NAME_EMAIL
      - SUBJECT_ALTERNATIVE_NAME_DNS. - Additional internal value ALL_SUBJECT_AND_ALTERNATIVE_NAMES
      is used automatically when usernameFrom=UPN.
    type: str
  description:
    description: Certificate Profile's description.
    type: str
  externalIdentityStoreName:
    description: Referred IDStore name for the Certificate Profile or not applicable
      in case no identity store is chosen.
    type: str
  id:
    description: Certificate Profile's id.
    type: str
  matchMode:
    description: Match mode of the Certificate Profile. Allowed values - NEVER - RESOLVE_IDENTITY_AMBIGUITY
      - BINARY_COMPARISON.
    type: str
  name:
    description: Certificate Profile's name.
    type: str
  usernameFrom:
    description: The attribute in the certificate where the user name should be taken
      from. Allowed values - CERTIFICATE (for a specific attribute as defined in certificateAttributeName)
      - UPN (for using any Subject or Alternative Name Attributes in the Certificate
      - an option only in AD).
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    certificate_profile.CertificateProfile.create_certificate_profile,
    certificate_profile.CertificateProfile.update_certificate_profile_by_id,

  - Paths used are
    post /ers/config/certificateprofile,
    put /ers/config/certificateprofile/{id},

"""

EXAMPLES = r"""
- name: Update by id
  cisco.ise.certificate_profile:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    allowedAsUserName: true
    certificateAttributeName: string
    description: string
    externalIdentityStoreName: string
    id: string
    matchMode: string
    name: string
    usernameFrom: string

- name: Create
  cisco.ise.certificate_profile:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    allowedAsUserName: true
    certificateAttributeName: string
    description: string
    externalIdentityStoreName: string
    id: string
    matchMode: string
    name: string
    usernameFrom: string

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
        ]
      }
    }
"""

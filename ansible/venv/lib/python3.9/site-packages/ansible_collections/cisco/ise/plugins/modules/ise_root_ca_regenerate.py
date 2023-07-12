#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: ise_root_ca_regenerate
short_description: Resource module for Ise Root CA Regenerate
description:
- Manage operation create of the resource Ise Root CA Regenerate.
- This API initiates regeneration of Cisco ISE root CA certificate chain.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  removeExistingISEIntermediateCSR:
    description: Setting this attribute to true removes existing Cisco ISE Intermediate
      CSR.
    type: bool
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for Certificates
  description: Complete reference of the Certificates API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!certificate-openapi
notes:
  - SDK Method used are
    certificates.Certificates.regenerate_ise_root_ca,

  - Paths used are
    post /api/v1/certs/ise-root-ca/regenerate,

"""

EXAMPLES = r"""
- name: Create
  cisco.ise.ise_root_ca_regenerate:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    removeExistingISEIntermediateCSR: true

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "id": "string",
        "link": {
          "href": "string",
          "rel": "string",
          "type": "string"
        },
        "message": "string"
      },
      "version": "string"
    }
"""

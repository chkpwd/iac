#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: licensing_registration_create
short_description: Resource module for Licensing Registration Create
description:
- Manage operation create of the resource Licensing Registration Create.
- License - Configure registration information.
version_added: '2.1.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  connectionType:
    description: Licensing Registration Create's connectionType.
    type: str
  registrationType:
    description: Licensing Registration Create's registrationType.
    type: str
  ssmOnPremServer:
    description: If connection type is selected as SSM_ONPREM_SERVER, then IP address
      or the hostname (or FQDN) of the SSM On-Prem server Host.
    type: str
  tier:
    description: Licensing Registration Create's tier.
    elements: str
    type: list
  token:
    description: Token.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for Licensing
  description: Complete reference of the Licensing API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!license-openapi
notes:
  - SDK Method used are
    licensing.Licensing.create_registration_info,

  - Paths used are
    post /api/v1/license/system/register,

"""

EXAMPLES = r"""
- name: Create
  cisco.ise.licensing_registration_create:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    connectionType: string
    registrationType: string
    ssmOnPremServer: string
    tier:
    - string
    token: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: str
  sample: >
    "'string'"
"""

#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: transport_gateway_settings
short_description: Resource module for Transport Gateway Settings
description:
- Manage operation update of the resource Transport Gateway Settings.
- Transport Gateway acts a proxy for the communication between the ISE servers in your network and the Telemetry servers in case of air-gapped network.
version_added: '2.1.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  enableTransportGateway:
    description: Indicates whether transport gateway is enabled or not.
    type: bool
  url:
    description: URL of transport gateway.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for telemetry
  description: Complete reference of the telemetry API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!system-settings-openapi
notes:
  - SDK Method used are
    telemetry.Telemetry.update_transport_gateway,

  - Paths used are
    put /api/v1/system-settings/telemetry/transport-gateway,

"""

EXAMPLES = r"""
- name: Update all
  cisco.ise.transport_gateway_settings:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    enableTransportGateway: true
    url: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "enableTransportGateway": true,
      "url": "string"
    }

ise_update_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "enableTransportGateway": true,
        "url": "string"
      },
      "version": "string"
    }
"""

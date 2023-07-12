#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: pan_ha_info
short_description: Information module for Pan Ha
description:
- Get all Pan Ha.
- >
   In a high availability configuration, the primary PAN is in active state. The secondary PAN backup PAN is in standby state, which means that it receives
   all the configuration updates from the primary PAN, but is not active in the Cisco ISE cluster. You can configure Cisco ISE to automatically promote the
   secondary PAN when the primary PAN becomes unavailable.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options: {}
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for PAN HA
  description: Complete reference of the PAN HA API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!deployment-openapi
notes:
  - SDK Method used are
    pan_ha.PanHa.get_pan_ha_status,

  - Paths used are
    get /api/v1/deployment/pan-ha,

"""

EXAMPLES = r"""
- name: Get all Pan Ha
  cisco.ise.pan_ha_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
  register: result

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "failedAttempts": 0,
      "isEnabled": true,
      "pollingInterval": 0,
      "primaryHealthCheckNode": {
        "hostname": "string"
      },
      "secondaryHealthCheckNode": {
        "hostname": "string"
      }
    }
"""

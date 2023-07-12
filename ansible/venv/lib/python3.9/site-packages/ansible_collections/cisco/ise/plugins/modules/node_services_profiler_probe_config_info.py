#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: node_services_profiler_probe_config_info
short_description: Information module for Node Services Profiler Probe Config
description:
- Get Node Services Profiler Probe Config by name.
- This API retrieves the profiler probe configuration of a PSN.
version_added: '2.1.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options:
  hostname:
    description:
    - Hostname path parameter. Hostname of the node.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for Node Services
  description: Complete reference of the Node Services API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!deployment-openapi
notes:
  - SDK Method used are
    node_services.NodeServices.get_profiler_probe_config,

  - Paths used are
    get /api/v1/profile/{hostname},

"""

EXAMPLES = r"""
- name: Get Node Services Profiler Probe Config by name
  cisco.ise.node_services_profiler_probe_config_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    hostname: string
  register: result

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "activeDirectory": {
        "daysBeforeRescan": 0
      },
      "dhcp": {
        "interfaces": [
          {
            "interface": "string"
          }
        ],
        "port": 0
      },
      "dhcpSpan": {
        "interfaces": [
          {
            "interface": "string"
          }
        ]
      },
      "dns": {
        "timeout": 0
      },
      "http": {
        "interfaces": [
          {
            "interface": "string"
          }
        ]
      },
      "netflow": {
        "interfaces": [
          {
            "interface": "string"
          }
        ],
        "port": 0
      },
      "nmap": [
        {}
      ],
      "pxgrid": [
        {}
      ],
      "radius": [
        {}
      ],
      "snmpQuery": {
        "eventTimeout": 0,
        "retries": 0,
        "timeout": 0
      },
      "snmpTrap": {
        "interfaces": [
          {
            "interface": "string"
          }
        ],
        "linkTrapQuery": true,
        "macTrapQuery": true,
        "port": 0
      }
    }
"""

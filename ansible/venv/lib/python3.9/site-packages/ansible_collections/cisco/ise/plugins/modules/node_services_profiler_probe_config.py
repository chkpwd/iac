#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: node_services_profiler_probe_config
short_description: Resource module for Node Services Profiler Probe Config
description:
- Manage operation update of the resource Node Services Profiler Probe Config.
- This API updates the profiler probe configuration of a PSN.
version_added: '2.1.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  activeDirectory:
    description: The Active Directory probe queries the Active Directory for Windows
      information.
    suboptions:
      daysBeforeRescan:
        description: Node Services Profiler Probe Config's daysBeforeRescan.
        type: int
    type: dict
  dhcp:
    description: The DHCP probe listens for DHCP packets from IP helpers.
    suboptions:
      interfaces:
        description: Node Services Profiler Probe Config's interfaces.
        elements: dict
        suboptions:
          interface:
            description: Node Services Profiler Probe Config's interface.
            type: str
        type: list
      port:
        description: Node Services Profiler Probe Config's port.
        type: int
    type: dict
  dhcpSpan:
    description: The DHCP SPAN probe collects DHCP packets.
    suboptions:
      interfaces:
        description: Node Services Profiler Probe Config's interfaces.
        elements: dict
        suboptions:
          interface:
            description: Node Services Profiler Probe Config's interface.
            type: str
        type: list
    type: dict
  dns:
    description: The DNS probe performs a DNS lookup for the FQDN.
    suboptions:
      timeout:
        description: Node Services Profiler Probe Config's timeout.
        type: int
    type: dict
  hostname:
    description: Hostname path parameter. Hostname of the node.
    type: str
  http:
    description: The HTTP probe receives and parses HTTP packets.
    suboptions:
      interfaces:
        description: Node Services Profiler Probe Config's interfaces.
        elements: dict
        suboptions:
          interface:
            description: Node Services Profiler Probe Config's interface.
            type: str
        type: list
    type: dict
  netflow:
    description: The NetFlow probe collects the NetFlow packets that are sent to it
      from routers.
    suboptions:
      interfaces:
        description: Node Services Profiler Probe Config's interfaces.
        elements: dict
        suboptions:
          interface:
            description: Node Services Profiler Probe Config's interface.
            type: str
        type: list
      port:
        description: Node Services Profiler Probe Config's port.
        type: int
    type: dict
  nmap:
    description: The NMAP probe scans endpoints for open ports and OS.
    elements: dict
    type: list
  pxgrid:
    description: The pxGrid probe fetches attributes of MAC address or IP address as
      a subscriber from the pxGrid queue.
    elements: dict
    type: list
  radius:
    description: The RADIUS probe collects RADIUS session attributes as well as CDP,
      LLDP, DHCP, HTTP, and MDM attributes from IOS Sensors.
    elements: dict
    type: list
  snmpQuery:
    description: The SNMP query probe collects details from network devices such as
      interface, CDP, LLDP, and ARP.
    suboptions:
      eventTimeout:
        description: Node Services Profiler Probe Config's eventTimeout.
        type: int
      retries:
        description: Node Services Profiler Probe Config's retries.
        type: int
      timeout:
        description: Node Services Profiler Probe Config's timeout.
        type: int
    type: dict
  snmpTrap:
    description: The SNMP trap probe receives linkup, linkdown, and MAC notification
      traps from network devices.
    suboptions:
      interfaces:
        description: Node Services Profiler Probe Config's interfaces.
        elements: dict
        suboptions:
          interface:
            description: Node Services Profiler Probe Config's interface.
            type: str
        type: list
      linkTrapQuery:
        description: LinkTrapQuery flag.
        type: bool
      macTrapQuery:
        description: MacTrapQuery flag.
        type: bool
      port:
        description: Node Services Profiler Probe Config's port.
        type: int
    type: dict
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for Node Services
  description: Complete reference of the Node Services API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!deployment-openapi
notes:
  - SDK Method used are
    node_services.NodeServices.set_profiler_probe_config,

  - Paths used are
    put /api/v1/profile/{hostname},

"""

EXAMPLES = r"""
- name: Update by name
  cisco.ise.node_services_profiler_probe_config:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    activeDirectory:
      daysBeforeRescan: 0
    dhcp:
      interfaces:
      - interface: string
      port: 0
    dhcpSpan:
      interfaces:
      - interface: string
    dns:
      timeout: 0
    hostname: string
    http:
      interfaces:
      - interface: string
    netflow:
      interfaces:
      - interface: string
      port: 0
    nmap:
    - {}
    pxgrid:
    - {}
    radius:
    - {}
    snmpQuery:
      eventTimeout: 0
      retries: 0
      timeout: 0
    snmpTrap:
      interfaces:
      - interface: string
      linkTrapQuery: true
      macTrapQuery: true
      port: 0

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

ise_update_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "success": {
        "message": "string"
      },
      "version": "string"
    }
"""

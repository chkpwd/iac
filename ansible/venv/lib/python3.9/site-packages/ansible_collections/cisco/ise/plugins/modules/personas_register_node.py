#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: personas_register_node
short_description: Register a node to the primary
description:
- Register a node to the primary
version_added: '2.4.0'
author: Rafael Campos (@racampos)
options:
  primary_ip:
    description:
    - The IP address of the primary node.
    type: str
  primary_username:
    description:
    - The username for the primary node.
    type: str
  primary_password:
    description:
    - The password for the primary node.
    type: str
  fqdn:
    description:
    - The fully qualified domain name of the node.
    type: str
  username:
    description:
    - The username to log into the node.
    type: str
  password:
    description:
    - The password to log into the node.
    type: str
  roles:
    description:
    - "The roles to be fulfilled by this node. Possible roles are PrimaryAdmin, SecondaryAdmin, \
      PrimaryMonitoring, SecondaryMonitoring, PrimaryDedicatedMonitoring, SecondaryDedicatedMonitoring, Standalone"
    type: list
    elements: str
  services:
    description:
    - The services this node will run. Possible services are Session, Profiler, TC-NAC, SXP, DeviceAdmin, PassiveIdentity, pxGrid, pxGridCloud
    type: list
    elements: str
  ise_verify:
    description:
    - Whether or not to verify the identity of the node.
    type: bool
  ise_version:
    description:
    - The version of the ISE node.
    type: str
  ise_wait_on_rate_limit:
    description:
    - Whether or not to wait on rate limit
    type: bool
requirements:
- requests >= 2.25.1
- python >= 3.5
seealso:
# Reference by module name
- module: cisco.ise.plugins.modules.personas_register_node
notes:
    - "Does not support C(check_mode)"
"""

EXAMPLES = r"""
- name: Register the secondary node and PSN nodes to the cluster
  cisco.ise.personas_register_node:
    primary_ip: 10.1.1.1
    primary_username: admin
    primary_password: Cisco123
    fqdn: "{{ item.fqdn }}"
    username: admin
    password: cisco123
    roles: "{{ item.roles }}"
    services: "{{ item.services }}"
  loop:
    - fqdn: ise-pan-server-2.example.com
      roles:
        - SecondaryAdmin
        - SecondaryMonitoring
      services: []
    - fqdn: ise-psn-server-1.example.com
      roles: []
      services:
        - Session
        - Profiler
    - fqdn: ise-psn-server-2.example.com
      roles: []
      services:
        - Session
        - Profiler
"""

RETURN = r"""
ise_response:
  description: A string stating that the node was successfully registered
  returned: always
  type: str
  sample: Node ise-pan-server-2 updated successfully
"""

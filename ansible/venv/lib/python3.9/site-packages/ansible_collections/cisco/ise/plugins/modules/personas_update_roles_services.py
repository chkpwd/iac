#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: personas_update_roles_services
short_description: Update the roles and services of a node
description:
- Update the roles and services of a node
version_added: '2.4.0'
author: Rafael Campos (@racampos)
options:
  ip:
    description:
    - The IP address of the node to be updated.
    type: str
  username:
    description:
    - The username to log into the node.
    type: str
  password:
    description:
    - The password to log into the node.
    type: str
  hostname:
    description:
    - The hostname of the node.
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
- module: cisco.ise.plugins.modules.personas_update_roles_services
notes:
    - "Does not support C(check_mode)"
"""

EXAMPLES = r"""
- name: Remove the Primary Monitoring role and the Session and Profiler services from the primary node
  cisco.ise.personas_update_roles_services:
    ip: 10.1.1.1
    username: admin
    password: C1sco123
    hostname: ise-pan-server-1
    roles:
      - PrimaryAdmin
    services: []
"""

RETURN = r"""
ise_response:
  description: A string stating that the node was successfully updated
  returned: always
  type: str
  sample: Node ise-pan-server-1 updated successfully
"""

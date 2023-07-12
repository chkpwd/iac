#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: personas_check_standalone
short_description: Ensure the node is in standalone mode
description:
- Ensure the mode is in standalone mode
version_added: '0.0.8'
author: Rafael Campos (@racampos)
options:
  ip:
    description:
    - The IP address of the node
    type: str
  username:
    description:
    - The username for the node.
    type: str
  password:
    description:
    - The password for the node.
    type: str
  hostname:
    description:
    - The hostname for the node for which the certificate will be exported.
    type: str
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
- module: cisco.ise.plugins.modules.personas_check_standalone
notes:
    - "Does not support C(check_mode)"
"""

EXAMPLES = r"""
- name: Check if all nodes are in STANDALONE state
  cisco.ise.personas_check_standalone:
    ip: "{{ item.ip }}"
    username: admin
    password: cisco123
    hostname: "{{ item.hostname }}"
  loop:
    - ip: 10.1.1.1
      hostname: ise-pan-server-1
    - ip: 10.1.1.2
      hostname: ise-pan-server-2
    - ip: 10.1.1.3
      hostname: ise-psn-server-1
    - ip: 10.1.1.4
      hostname: ise-psn-server-2
"""

RETURN = r"""
ise_response:
  description: A string stating that the node is in standalone mode
  returned: always
  type: str
  sample: Node ise-pan-server-1 is in STANDALONE mode
"""

#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: personas_export_certs
short_description: Export certificate into primary node
description:
- Export certificate into primary node
version_added: '0.0.8'
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
  name:
    description:
    - The name of the node for which the certificate will be exported.
    type: str
  ip:
    description:
    - The IP address of the node for which the certificate will be exported.
    type: str
  hostname:
    description:
    - The hostname for the node for which the certificate will be exported.
    type: str
  username:
    description:
    - The username for the node for which the certificate will be exported.
    type: str
  password:
    description:
    - The password for the node for which the certificate will be exported.
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
- module: cisco.ise.plugins.modules.personas_export_certs
notes:
    - "Does not support C(check_mode)"
"""

EXAMPLES = r"""
- name: Export trusted certificates into primary node
  cisco.ise.personas_export_certs:
    primary_ip: 10.1.1.1
    primary_username: admin
    primary_password: cisco123
    name: "{{ item.name }}"
    ip: "{{ item.ip }}"
    hostname: "{{ item.hostname }}"
    username: admin
    password: cisco123
  loop:
    - name: ISE PAN Server 2
      ip: 10.1.1.2
      hostname: ise-pan-server-2
    - name: ISE PSN Server 1
      ip: 10.1.1.3
      hostname: ise-psn-server-1
    - name: ISE PSN Server 2
      ip: 10.1.1.4
      hostname: ise-psn-server-2
"""

RETURN = r"""
ise_response:
  description: A text string stating that the certificate was exported successfully.
  returned: always
  type: str
  sample: The certificate for ISE PAN Server 2 was exported successfully to the primary node
"""

#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: mnt_session_by_ip_info
short_description: Information module for MNT Session By Ip
description:
- Get MNT Session By Ip by id.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options:
  endpoint_ipv4:
    description:
    - Endpoint_ipv4 path parameter.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    misc.Misc.get_sessions_by_endpoint_ip,

  - Paths used are
    get /Session/EndPointIPAddress/{endpoint_ipv4},

"""

EXAMPLES = r"""
- name: Get MNT Session By Ip by id
  cisco.ise.mnt_session_by_ip_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    endpoint_ipv4: string
  register: result

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""

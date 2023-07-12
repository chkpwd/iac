#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: mnt_session_reauthentication_info
short_description: Information module for MNT Session Reauthentication
description:
- Get MNT Session Reauthentication by id.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options:
  PSN_NAME:
    description:
    - PSN_NAME path parameter.
    type: str
  ENDPOINT_MAC:
    description:
    - ENDPOINT_MAC path parameter.
    type: str
  REAUTH_TYPE:
    description:
    - REAUTH_TYPE path parameter.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    misc.Misc.session_reauthentication_by_mac,

  - Paths used are
    get /CoA/Reauth/{PSN_NAME}/{ENDPOINT_MAC}/{REAUTH_TYPE},

"""

EXAMPLES = r"""
- name: Get MNT Session Reauthentication by id
  cisco.ise.mnt_session_reauthentication_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    PSN_NAME: string
    ENDPOINT_MAC: string
    REAUTH_TYPE: string
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

#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: mnt_sessions_by_session_id_info
short_description: Information module for MNT Sessions By Session Id
description:
- Get all MNT Sessions By Session Id.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options:
  session_id:
    description:
    - Session_id path parameter.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    misc.Misc.get_sessions_by_session_id,

  - Paths used are
    get /Session/Active/SessionID/{session_id}/0,

"""

EXAMPLES = r"""
- name: Get all MNT Sessions By Session Id
  cisco.ise.mnt_sessions_by_session_id_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    session_id: string
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

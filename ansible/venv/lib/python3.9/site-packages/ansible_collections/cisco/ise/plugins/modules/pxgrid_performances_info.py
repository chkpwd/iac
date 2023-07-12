#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: pxgrid_performances_info
short_description: Information module for pxGrid Performances Info
description:
- Get pxGrid Performances Info.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options: {}
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    system_health.SystemHealth.get_performances,

  - Paths used are
    post /ise/system/getPerformances,

"""

EXAMPLES = r"""
- name: Get all pxGrid Performances Info
  cisco.ise.pxgrid_performances_info:
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
    {}
"""

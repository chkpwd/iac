#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: system_config_version_info
short_description: Information module for System Config Version
description:
- Get all System Config Version.
- This API allows the client to get Cisco ISE version and patch information.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options: {}
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for VersionAndPatch
  description: Complete reference of the VersionAndPatch API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!iseversion
notes:
  - SDK Method used are
    version_and_patch.VersionAndPatch.get_ise_version_and_patch,

  - Paths used are
    get /ers/config/op/systemconfig/iseversion,

"""

EXAMPLES = r"""
- name: Get all System Config Version
  cisco.ise.system_config_version_info:
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
    {
      "resultValue": [
        {
          "value": "string",
          "name": "string"
        }
      ]
    }
"""

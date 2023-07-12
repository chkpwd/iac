#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: aci_test_connectivity
short_description: Resource module for ACI Test Connectivity
description:
- Manage operation update of the resource ACI Test Connectivity.
- This API allows the client to test ACI Domain Manager connection.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options: {}
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    aci_settings.AciSettings.test_aci_connectivity,

  - Paths used are
    put /ers/config/acisettings/testACIConnectivity,

"""

EXAMPLES = r"""
- name: Update all
  cisco.ise.aci_test_connectivity:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "ACITestConnectionResult": {
        "result": true
      }
    }
"""

#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: threat_vulnerabilities_clear
short_description: Resource module for Threat Vulnerabilities Clear
description:
- Manage operation update of the resource Threat Vulnerabilities Clear.
- This API allows the client to delete the ThreatContext and Threat events that.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  macAddresses:
    description: Threat Vulnerabilities Clear's macAddresses.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for ClearThreatsAndVulnerabilities
  description: Complete reference of the ClearThreatsAndVulnerabilities API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!clearthreatsandvulneribilities
notes:
  - SDK Method used are
    clear_threats_and_vulnerabilities.ClearThreatsAndVulnerabilities.clear_threats_and_vulnerabilities,

  - Paths used are
    put /ers/config/threat/clearThreatsAndVulneribilities,

"""

EXAMPLES = r"""
- name: Update all
  cisco.ise.threat_vulnerabilities_clear:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    macAddresses: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""

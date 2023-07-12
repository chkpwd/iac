#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: syslog_config_update
short_description: Resource module for Syslog Config Update
description:
- Manage operation update of the resource Syslog Config Update.
- Update Syslog Destination.
version_added: '6.0.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  configId:
    description: Required only for update syslog configuration.
    type: str
  description:
    description: Description.
    type: str
  host:
    description: Host.
    type: str
  name:
    description: Name.
    type: str
  port:
    description: Port.
    type: str
  protocol:
    description: Protocol.
    type: str
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for Event Management UpdateSyslogDestination
  description: Complete reference of the UpdateSyslogDestination API.
  link: https://developer.cisco.com/docs/dna-center/#!update-syslog-destination
notes:
  - SDK Method used are
    event_management.EventManagement.update_syslog_destination,

  - Paths used are
    put /dna/intent/api/v1/event/syslogConfig,

"""

EXAMPLES = r"""
- name: Update all
  cisco.dnac.syslog_config_update:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    configId: string
    description: string
    host: string
    name: string
    port: string
    protocol: string

"""

RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "errorMessage": {
        "errors": [
          "string"
        ]
      },
      "apiStatus": "string",
      "statusMessage": "string"
    }
"""

#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: event_webhook_create
short_description: Resource module for Event Webhook Create
description:
- Manage operation create of the resource Event Webhook Create.
- Create Webhook Destination.
version_added: '6.0.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  description:
    description: Description.
    type: str
  headers:
    description: Event Webhook Create's headers.
    elements: dict
    suboptions:
      defaultValue:
        description: Default Value.
        type: str
      encrypt:
        description: Encrypt.
        type: bool
      name:
        description: Name.
        type: str
      value:
        description: Value.
        type: str
    type: list
  method:
    description: Method.
    type: str
  name:
    description: Name.
    type: str
  trustCert:
    description: Trust Cert.
    type: bool
  url:
    description: Url.
    type: str
  webhookId:
    description: Required only for update webhook configuration.
    type: str
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for Event Management CreateWebhookDestination
  description: Complete reference of the CreateWebhookDestination API.
  link: https://developer.cisco.com/docs/dna-center/#!create-webhook-destination
notes:
  - SDK Method used are
    event_management.EventManagement.create_webhook_destination,

  - Paths used are
    post /dna/intent/api/v1/event/webhook,

"""

EXAMPLES = r"""
- name: Create
  cisco.dnac.event_webhook_create:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    description: string
    headers:
    - defaultValue: string
      encrypt: true
      name: string
      value: string
    method: string
    name: string
    trustCert: true
    url: string
    webhookId: string

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

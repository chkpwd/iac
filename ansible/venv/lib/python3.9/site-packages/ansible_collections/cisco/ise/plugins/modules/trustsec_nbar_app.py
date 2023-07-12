#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: trustsec_nbar_app
short_description: Resource module for Trustsec NBAR App
description:
- Manage operations create, update and delete of the resource Trustsec NBAR App.
- Create NBAR application.
- Update NBAR Application.
version_added: '2.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  description:
    description: Trustsec NBAR App's description.
    type: str
  id:
    description: Trustsec NBAR App's id.
    type: str
  name:
    description: Trustsec NBAR App's name.
    type: str
  networkIdentities:
    description: Array of NIs.
    elements: dict
    suboptions:
      ports:
        description: Trustsec NBAR App's ports.
        type: str
      protocol:
        description: Trustsec NBAR App's protocol.
        type: str
    type: list
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for nbarApp
  description: Complete reference of the nbarApp API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!trustsec-openapi
notes:
  - SDK Method used are
    nbar_app.NbarApp.create_nbar_app,
    nbar_app.NbarApp.delete_nbar_app_by_id,
    nbar_app.NbarApp.update_nbar_app_by_id,

  - Paths used are
    post /api/v1/trustsec/sgacl/nbarapp,
    delete /api/v1/trustsec/sgacl/nbarapp/{id},
    put /api/v1/trustsec/sgacl/nbarapp/{id},

"""

EXAMPLES = r"""
- name: Create
  cisco.ise.trustsec_nbar_app:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    description: string
    id: string
    name: string
    networkIdentities:
    - ports: string
      protocol: string

- name: Update by id
  cisco.ise.trustsec_nbar_app:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    description: string
    id: string
    name: string
    networkIdentities:
    - ports: string
      protocol: string

- name: Delete by id
  cisco.ise.trustsec_nbar_app:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    id: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: list
  elements: dict
  sample: >
    [
      {
        "description": "string",
        "id": "string",
        "name": "string",
        "networkIdentities": [
          {
            "ports": "string",
            "protocol": "string"
          }
        ]
      }
    ]

ise_update_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "code": 0,
      "message": "string"
    }
"""

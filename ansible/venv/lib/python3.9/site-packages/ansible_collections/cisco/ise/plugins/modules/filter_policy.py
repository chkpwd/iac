#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: filter_policy
short_description: Resource module for Filter Policy
description:
- Manage operations create, update and delete of the resource Filter Policy.
- This API creates a filter policy.
- This API deletes a filter policy.
- This API allows the client to update a filter policy.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  domains:
    description: List of SXP Domains, separated with comma.
    type: str
  id:
    description: Id path parameter.
    type: str
  sgt:
    description: SGT name or ID. At least one of subnet or sgt or vn should be defined.
    type: str
  subnet:
    description: Subnet for filter policy (hostname is not supported). At least one
      of subnet or sgt or vn should be defined.
    type: str
  vn:
    description: Virtual Network. At least one of subnet or sgt or vn should be defined.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    filter_policy.FilterPolicy.create_filter_policy,
    filter_policy.FilterPolicy.delete_filter_policy_by_id,
    filter_policy.FilterPolicy.update_filter_policy_by_id,

  - Paths used are
    post /ers/config/filterpolicy,
    delete /ers/config/filterpolicy/{id},
    put /ers/config/filterpolicy/{id},

"""

EXAMPLES = r"""
- name: Update by id
  cisco.ise.filter_policy:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    domains: string
    id: string
    sgt: string
    subnet: string
    vn: string

- name: Delete by id
  cisco.ise.filter_policy:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    id: string

- name: Create
  cisco.ise.filter_policy:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    domains: string
    sgt: string
    subnet: string
    vn: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "subnet": "string",
      "domains": "string",
      "sgt": "string",
      "vn": "string"
    }

ise_update_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  version_added: '1.1.0'
  type: dict
  sample: >
    {
      "UpdatedFieldsList": {
        "updatedField": [
          {
            "field": "string",
            "oldValue": "string",
            "newValue": "string"
          }
        ],
        "field": "string",
        "oldValue": "string",
        "newValue": "string"
      }
    }
"""

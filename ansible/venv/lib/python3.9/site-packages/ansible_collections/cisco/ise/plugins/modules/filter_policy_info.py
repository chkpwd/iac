#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: filter_policy_info
short_description: Information module for Filter Policy
description:
- Get all Filter Policy.
- Get Filter Policy by id.
- This API allows the client to get a filter policy by ID.
- This API allows the client to get all the filter policies.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options:
  id:
    description:
    - Id path parameter.
    type: str
  page:
    description:
    - Page query parameter. Page number.
    type: int
  size:
    description:
    - Size query parameter. Number of objects returned per page.
    type: int
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    filter_policy.FilterPolicy.get_filter_policy_by_id,
    filter_policy.FilterPolicy.get_filter_policy_generator,

  - Paths used are
    get /ers/config/filterpolicy,
    get /ers/config/filterpolicy/{id},

"""

EXAMPLES = r"""
- name: Get all Filter Policy
  cisco.ise.filter_policy_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    page: 1
    size: 20
  register: result

- name: Get Filter Policy by id
  cisco.ise.filter_policy_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    id: string
  register: result

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

ise_responses:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  version_added: '1.1.0'
  type: list
  elements: dict
  sample: >
    [
      {
        "subnet": "string",
        "domains": "string",
        "sgt": "string",
        "vn": "string"
      }
    ]
"""

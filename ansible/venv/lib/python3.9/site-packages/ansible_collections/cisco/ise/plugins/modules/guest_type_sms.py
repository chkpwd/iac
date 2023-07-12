#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: guest_type_sms
short_description: Resource module for Guest Type SMS
description:
- Manage operation update of the resource Guest Type SMS.
- This API allows the client to update a guest type sms by ID.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  additionalData:
    description: Guest Type SMS's additionalData.
    elements: dict
    suboptions:
      name:
        description: Guest Type SMS's name.
        type: str
      value:
        description: Guest Type SMS's value.
        type: str
    type: list
  id:
    description: Id path parameter.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    guest_type.GuestType.update_guest_type_sms,

  - Paths used are
    put /ers/config/guesttype/sms/{id},

"""

EXAMPLES = r"""
- name: Update by id
  cisco.ise.guest_type_sms:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    additionalData:
    - name: phoneNumber
      value: phoneNumber
    - name: serviceProvider
      value: serviceProvider
    id: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""

#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: guest_user_suspend
short_description: Resource module for Guest User Suspend
description:
- Manage operation update of the resource Guest User Suspend.
- This API allows the client to suspend a guest user by ID.
- This API allows the client to suspend a guest user by name.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  additionalData:
    description: Guest User Suspend's additionalData.
    elements: dict
    suboptions:
      name:
        description: Guest User Suspend's name.
        type: str
      value:
        description: Guest User Suspend's value.
        type: str
    type: list
  id:
    description: Id path parameter.
    type: str
  name:
    description: Name path parameter.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    guest_user.GuestUser.suspend_guest_user_by_id,
    guest_user.GuestUser.suspend_guest_user_by_name,

  - Paths used are
    put /ers/config/guestuser/suspend/name/{name},
    put /ers/config/guestuser/suspend/{id},

"""

EXAMPLES = r"""
- name: Update by name
  cisco.ise.guest_user_suspend:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    name: string

- name: Update by id
  cisco.ise.guest_user_suspend:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    additionalData:
    - name: reason
      value: reason
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

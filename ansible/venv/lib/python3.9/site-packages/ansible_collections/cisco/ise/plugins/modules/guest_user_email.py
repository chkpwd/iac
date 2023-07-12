#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: guest_user_email
short_description: Resource module for Guest User Email
description:
- Manage operation update of the resource Guest User Email.
- This API allows the client to update a guest user email by ID.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  additionalData:
    description: Guest User Email's additionalData.
    elements: dict
    suboptions:
      name:
        description: Guest User Email's name.
        type: str
      value:
        description: Guest User Email's value.
        type: str
    type: list
  id:
    description: Id path parameter.
    type: str
  portalId:
    description: PortalId path parameter.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    guest_user.GuestUser.update_guest_user_email,

  - Paths used are
    put /ers/config/guestuser/email/{id}/portalId/{portalId},

"""

EXAMPLES = r"""
- name: Update by id
  cisco.ise.guest_user_email:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    additionalData:
    - name: senderEmail
      value: senderEmail
    id: string
    portalId: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""

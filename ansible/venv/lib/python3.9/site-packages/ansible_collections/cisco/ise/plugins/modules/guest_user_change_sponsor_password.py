#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: guest_user_change_sponsor_password
short_description: Resource module for Guest User Change Sponsor Password
description:
- Manage operation update of the resource Guest User Change Sponsor Password.
- This API allows the client to change the sponsor password.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  additionalData:
    description: Guest User Change Sponsor Password's additionalData.
    elements: dict
    suboptions:
      name:
        description: Guest User Change Sponsor Password's name.
        type: str
      value:
        description: Guest User Change Sponsor Password's value.
        type: str
    type: list
  portalId:
    description: PortalId path parameter.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    guest_user.GuestUser.change_sponsor_password,

  - Paths used are
    put /ers/config/guestuser/changeSponsorPassword/{portalId},

"""

EXAMPLES = r"""
- name: Update by id
  cisco.ise.guest_user_change_sponsor_password:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    additionalData:
    - name: currentPassword
      value: password
    - name: newPassword
      value: password
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

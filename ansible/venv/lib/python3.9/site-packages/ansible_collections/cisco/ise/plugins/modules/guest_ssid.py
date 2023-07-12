#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: guest_ssid
short_description: Resource module for Guest SSID
description:
- Manage operations create, update and delete of the resource Guest SSID.
- This API creates a guest SSID.
- This API deletes a guest SSID by ID.
- This API allows the client to update a guest SSID by ID.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  id:
    description: Guest SSID's id.
    type: str
  name:
    description: Resource Name. Name may contain alphanumeric or any of the following
      characters _.-.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    guest_ssid.GuestSsid.create_guest_ssid,
    guest_ssid.GuestSsid.delete_guest_ssid_by_id,
    guest_ssid.GuestSsid.update_guest_ssid_by_id,

  - Paths used are
    post /ers/config/guestssid,
    delete /ers/config/guestssid/{id},
    put /ers/config/guestssid/{id},

"""

EXAMPLES = r"""
- name: Update by id
  cisco.ise.guest_ssid:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    id: string
    name: string

- name: Delete by id
  cisco.ise.guest_ssid:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    id: string

- name: Create
  cisco.ise.guest_ssid:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    name: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "id": "string",
      "name": "string",
      "link": {
        "rel": "string",
        "href": "string",
        "type": "string"
      }
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

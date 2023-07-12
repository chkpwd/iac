#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: portal_theme
short_description: Resource module for Portal Theme
description:
- Manage operations create, update and delete of the resource Portal Theme.
- This API creates a portal theme.
- This API deletes a portal theme by ID.
- This API allows the client to update a portal theme by ID.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  description:
    description: Portal Theme's description.
    type: str
  id:
    description: Portal Theme's id.
    type: str
  name:
    description: Portal Theme's name.
    type: str
  themeData:
    description: Portal Theme for all portals.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    portal_theme.PortalTheme.create_portal_theme,
    portal_theme.PortalTheme.delete_portal_theme_by_id,
    portal_theme.PortalTheme.update_portal_theme_by_id,

  - Paths used are
    post /ers/config/portaltheme,
    delete /ers/config/portaltheme/{id},
    put /ers/config/portaltheme/{id},

"""

EXAMPLES = r"""
- name: Update by id
  cisco.ise.portal_theme:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    description: string
    id: string
    name: string
    themeData: string

- name: Delete by id
  cisco.ise.portal_theme:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    id: string

- name: Create
  cisco.ise.portal_theme:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    description: string
    name: string
    themeData: string

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
      "description": "string",
      "themeData": "string",
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

#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: internal_user
short_description: Resource module for Internal User
description:
- Manage operations create, update and delete of the resource Internal User.
- This API creates an internal user.
- This API deletes an internal user by ID.
- This API deletes an internal user by name.
- This API allows the client to update an internal user by ID.
- This API allows the client to update an internal user by name.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  changePassword:
    description: ChangePassword flag.
    type: bool
  customAttributes:
    description: Key value map.
    type: dict
  description:
    description: Internal User's description.
    type: str
  email:
    description: Internal User's email.
    type: str
  enablePassword:
    description: Internal User's enablePassword.
    type: str
  enabled:
    description: Whether the user is enabled/disabled. To use it as filter, the values
      should be 'Enabled' or 'Disabled'. The values are case sensitive. For example,
      'ERSObjectURL?filter=enabled.EQ.Enabled'.
    type: bool
  expiryDate:
    description: To store the internal user's expiry date information. It's format is
      = 'YYYY-MM-DD'.
    type: str
  expiryDateEnabled:
    description: ExpiryDateEnabled flag.
    type: bool
  firstName:
    description: Internal User's firstName.
    type: str
  id:
    description: Internal User's id.
    type: str
  identityGroups:
    description: CSV of identity group IDs.
    type: str
  lastName:
    description: Internal User's lastName.
    type: str
  name:
    description: Internal User's name.
    type: str
  password:
    description: Internal User's password.
    type: str
  passwordIDStore:
    description: The id store where the internal user's password is kept.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    internal_user.InternalUser.create_internal_user,
    internal_user.InternalUser.delete_internal_user_by_id,
    internal_user.InternalUser.delete_internal_user_by_name,
    internal_user.InternalUser.update_internal_user_by_id,
    internal_user.InternalUser.update_internal_user_by_name,

  - Paths used are
    post /ers/config/internaluser,
    delete /ers/config/internaluser/name/{name},
    delete /ers/config/internaluser/{id},
    put /ers/config/internaluser/name/{name},
    put /ers/config/internaluser/{id},

"""

EXAMPLES = r"""
- name: Update by name
  cisco.ise.internal_user:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    changePassword: true
    customAttributes: {}
    description: string
    email: string
    enablePassword: string
    enabled: true
    expiryDate: string
    expiryDateEnabled: true
    firstName: string
    id: string
    identityGroups: string
    lastName: string
    name: string
    password: string
    passwordIDStore: string

- name: Delete by name
  cisco.ise.internal_user:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    name: string

- name: Update by id
  cisco.ise.internal_user:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    changePassword: true
    customAttributes: {}
    description: string
    email: string
    enablePassword: string
    enabled: true
    expiryDate: string
    expiryDateEnabled: true
    firstName: string
    id: string
    identityGroups: string
    lastName: string
    name: string
    password: string
    passwordIDStore: string

- name: Delete by id
  cisco.ise.internal_user:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    id: string

- name: Create
  cisco.ise.internal_user:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    changePassword: true
    customAttributes: {}
    description: string
    email: string
    enablePassword: string
    enabled: true
    expiryDate: string
    expiryDateEnabled: true
    firstName: string
    identityGroups: string
    lastName: string
    name: string
    password: string
    passwordIDStore: string

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
      "enabled": true,
      "email": "string",
      "password": "string",
      "firstName": "string",
      "lastName": "string",
      "changePassword": true,
      "identityGroups": "string",
      "expiryDateEnabled": true,
      "expiryDate": "string",
      "enablePassword": "string",
      "customAttributes": {},
      "passwordIDStore": "string",
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

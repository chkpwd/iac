#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: user
short_description: Resource module for User
description:
- Manage operations create and update of the resource User.
- Add a new user for Cisco DNA Center system.
- Update a user for Cisco DNA Center system.
version_added: '6.7.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  email:
    description: Email.
    type: str
  firstName:
    description: First Name.
    type: str
  lastName:
    description: Last Name.
    type: str
  password:
    description: Password.
    type: str
  roleList:
    description: Role id list.
    elements: str
    type: list
  userId:
    description: User Id.
    type: str
  username:
    description: Username.
    type: str
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for User and Roles AddUserAPI
  description: Complete reference of the AddUserAPI API.
  link: https://developer.cisco.com/docs/dna-center/#!add-user-api
- name: Cisco DNA Center documentation for User and Roles UpdateUserAPI
  description: Complete reference of the UpdateUserAPI API.
  link: https://developer.cisco.com/docs/dna-center/#!update-user-api
notes:
  - SDK Method used are
    userand_roles.UserandRoles.add_user_ap_i,
    userand_roles.UserandRoles.update_user_ap_i,

  - Paths used are
    post /dna/system/api/v1/user,
    put /dna/system/api/v1/user,

"""

EXAMPLES = r"""
- name: Create
  cisco.dnac.user:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    email: string
    firstName: string
    lastName: string
    password: string
    roleList:
    - string
    username: string

- name: Update all
  cisco.dnac.user:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    email: string
    firstName: string
    lastName: string
    roleList:
    - string
    userId: string
    username: string

"""

RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "message": "string",
      "userId": "string"
    }
"""

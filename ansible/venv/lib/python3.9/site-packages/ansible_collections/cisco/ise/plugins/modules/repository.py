#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: repository
short_description: Resource module for Repository
description:
- Manage operations create, update and delete of the resource Repository.
- Create a new repository in the system. The name provided for the repository must be unique.
- Long description TBD.
- Update the definition of a specific repository, providing ALL parameters for the repository.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  enablePki:
    description: EnablePki flag.
    type: bool
  name:
    description: Repository name should be less than 80 characters and can contain alphanumeric,
      underscore, hyphen and dot characters.
    type: str
  password:
    description: Password can contain alphanumeric and/or special characters.
    type: str
  path:
    description: Path should always start with "/" and can contain alphanumeric, underscore,
      hyphen and dot characters.
    type: str
  protocol:
    description: Repository's protocol.
    type: str
  repositoryName:
    description: RepositoryName path parameter. Unique name for a repository.
    type: str
  serverName:
    description: Repository's serverName.
    type: str
  userName:
    description: Username may contain alphanumeric and _-./@\\$ characters.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for Repository
  description: Complete reference of the Repository API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!repository-openapi
notes:
  - SDK Method used are
    repository.Repository.create_repository,
    repository.Repository.delete_repository,
    repository.Repository.update_repository,

  - Paths used are
    post /api/v1/repository,
    delete /api/v1/repository/{repositoryName},
    put /api/v1/repository/{repositoryName},

"""

EXAMPLES = r"""
- name: Create
  cisco.ise.repository:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    enablePki: true
    name: string
    password: string
    path: string
    protocol: string
    serverName: string
    userName: string

- name: Update by name
  cisco.ise.repository:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    enablePki: true
    name: string
    password: string
    path: string
    protocol: string
    repositoryName: string
    serverName: string
    userName: string

- name: Delete by name
  cisco.ise.repository:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    repositoryName: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "name": "string",
      "protocol": "string",
      "path": "string",
      "password": "string",
      "serverName": "string",
      "userName": "string",
      "enablePki": true
    }

ise_update_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  version_added: '1.1.0'
  type: dict
  sample: >
    {
      "success": {
        "message": "string"
      },
      "version": "string"
    }
"""

#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: repository_files_info
short_description: Information module for Repository Files
description:
- Get all Repository Files.
- This will get the full list of files present in the named repository.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options:
  repositoryName:
    description:
    - RepositoryName path parameter. Unique name for a repository.
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
    repository.Repository.get_repository_files,

  - Paths used are
    get /api/v1/repository/{repositoryName}/files,

"""

EXAMPLES = r"""
- name: Get all Repository Files
  cisco.ise.repository_files_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    repositoryName: string
  register: result

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: list
  elements: str
  sample: >
    [
      "string"
    ]
"""

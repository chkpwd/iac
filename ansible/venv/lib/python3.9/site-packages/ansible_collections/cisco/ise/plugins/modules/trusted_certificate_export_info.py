#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: trusted_certificate_export_info
short_description: Information module for Trusted Certificate Export
description:
- Get Trusted Certificate Export by id.
- The response of this API carries a trusted certificate file mapped to the.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options:
  id:
    description:
    - Id path parameter. ID of the Trusted Certificate to be exported.
    type: str
  dirPath:
    description:
    - Directory absolute path. Defaults to the current working directory.
    type: str
  saveFile:
    description:
    - Enable or disable automatic file creation of raw response.
    type: bool
  filename:
    description:
    - The filename used to save the download file.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for Certificates
  description: Complete reference of the Certificates API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!certificate-openapi
notes:
  - SDK Method used are
    certificates.Certificates.export_trusted_certificate,

  - Paths used are
    get /api/v1/certs/trusted-certificate/export/{id},

"""

EXAMPLES = r"""
- name: Get Trusted Certificate Export by id
  cisco.ise.trusted_certificate_export_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    id: string
  register: result

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "data": "filecontent",
      "filename": "filename",
      "dirpath": "download/directory",
      "path": "download/directory/filename"
    }
"""

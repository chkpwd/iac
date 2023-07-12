#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: system_certificate_export_info
short_description: Information module for System Certificate Export Info
description:
- Get System Certificate Export Info.
- Export System Certificate.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options:
  dirPath:
    description: Directory absolute path. Defaults to the current working directory.
    type: str
  export:
    description: System Certificate Export Info's export.
    type: str
  filename:
    description: The filename used to save the download file.
    type: str
  id:
    description: System Certificate Export Info's id.
    type: str
  password:
    description: System Certificate Export Info's password.
    type: str
  saveFile:
    description: Enable or disable automatic file creation of raw response.
    type: bool
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for Certificates
  description: Complete reference of the Certificates API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!certificate-openapi
notes:
  - SDK Method used are
    certificates.Certificates.export_system_certificate,

  - Paths used are

"""

EXAMPLES = r"""
- name: Create
  cisco.ise.system_certificate_export_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    dirPath: /tmp/downloads/
    export: string
    filename: download_filename.extension
    id: string
    password: string
    saveFile: true

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: str
  sample: >
    "'string'"
"""

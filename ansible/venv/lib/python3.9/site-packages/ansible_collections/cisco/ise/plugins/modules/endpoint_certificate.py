#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: endpoint_certificate
short_description: Resource module for Endpoint Certificate
description:
- Manage operation update of the resource Endpoint Certificate.
- This API allows the client to create an endpoint certificate.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  certTemplateName:
    description: Name of an Internal CA template.
    type: str
  certificateRequest:
    description: Key value map. Must have CN and SAN entries.
    suboptions:
      cn:
        description: Matches the requester's User Name, unless the Requester is an ERS
          Admin. ERS Admins are allowed to create requests for any CN.
        type: str
      san:
        description: Valid MAC Address, delimited by '-'.
        type: str
    type: dict
  dirPath:
    description: Directory absolute path. Defaults to the current working directory.
    type: str
  filename:
    description: The filename used to save the download file.
    type: str
  format:
    description: Allowed values - PKCS12, - PKCS12_CHAIN, - PKCS8, - PKCS8_CHAIN.
    type: str
  password:
    description: Protects the private key. Must have more than 8 characters, less than
      15 characters, at least one upper case letter, at least one lower case letter,
      at least one digit, and can only contain A-Za-z0-9_#.
    type: str
  saveFile:
    description: Enable or disable automatic file creation of raw response.
    type: bool
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for EndpointCertificate
  description: Complete reference of the EndpointCertificate API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!endpointcert
notes:
  - SDK Method used are
    endpoint_certificate.EndpointCertificate.create_endpoint_certificate,

  - Paths used are
    put /ers/config/endpointcert/certRequest,

"""

EXAMPLES = r"""
- name: Create
  cisco.ise.endpoint_certificate:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    certTemplateName: string
    certificateRequest:
      cn: string
      san: string
    dirPath: /tmp/downloads/
    filename: download_filename.extension
    format: string
    password: string
    saveFile: true

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

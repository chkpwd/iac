#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: csr_delete
short_description: Resource module for CSR Delete
description:
- Manage operation delete of the resource CSR Delete.
- This API deletes a Certificate Signing Request of a particular node based on given HostName and ID.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  hostName:
    description: HostName path parameter. Name of the host of which CSR's should be
      deleted.
    type: str
  id:
    description: Id path parameter. ID of the Certificate Signing Request to be deleted.
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
    certificates.Certificates.delete_csr_by_id,

  - Paths used are
    delete /api/v1/certs/certificate-signing-request/{hostName}/{id},

"""

EXAMPLES = r"""
- name: Delete by id
  cisco.ise.csr_delete:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    hostName: string
    id: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "message": "string"
      },
      "version": "string"
    }
"""

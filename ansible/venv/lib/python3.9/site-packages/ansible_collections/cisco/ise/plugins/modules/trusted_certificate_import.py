#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: trusted_certificate_import
short_description: Resource module for Trusted Certificate Import
description:
- Manage operation create of the resource Trusted Certificate Import.
- Import an X509 certificate as a trust certificate.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  allowBasicConstraintCAFalse:
    description: Allow certificates with Basic Constraints CA Field as False (required).
    type: bool
  allowOutOfDateCert:
    description: Allow out of date certificates (required).
    type: bool
  allowSHA1Certificates:
    description: Allow SHA1 based certificates (required).
    type: bool
  data:
    description: Certificate content (required).
    type: str
  description:
    description: Description of the certificate.
    type: str
  name:
    description: Name of the certificate.
    type: str
  trustForCertificateBasedAdminAuth:
    description: Trust for Certificate based Admin authentication.
    type: bool
  trustForCiscoServicesAuth:
    description: Trust for authentication of Cisco Services.
    type: bool
  trustForClientAuth:
    description: Trust for client authentication and Syslog.
    type: bool
  trustForIseAuth:
    description: Trust for authentication within Cisco ISE.
    type: bool
  validateCertificateExtensions:
    description: Validate trust certificate extension.
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
    certificates.Certificates.import_trust_certificate,

  - Paths used are
    post /api/v1/certs/trusted-certificate/import,

"""

EXAMPLES = r"""
- name: Create
  cisco.ise.trusted_certificate_import:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    allowBasicConstraintCAFalse: true
    allowOutOfDateCert: true
    allowSHA1Certificates: true
    data: string
    description: string
    name: string
    trustForCertificateBasedAdminAuth: true
    trustForCiscoServicesAuth: true
    trustForClientAuth: true
    trustForIseAuth: true
    validateCertificateExtensions: true

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "id": "string",
        "message": "string",
        "status": "string"
      },
      "version": "string"
    }
"""

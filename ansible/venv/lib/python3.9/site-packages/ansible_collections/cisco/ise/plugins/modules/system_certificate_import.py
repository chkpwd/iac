#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: system_certificate_import
short_description: Resource module for System Certificate Import
description:
- Manage operation create of the resource System Certificate Import.
- Import an X509 certificate as a system certificate.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  admin:
    description: Use certificate to authenticate the Cisco ISE Admin Portal.
    type: bool
  allowExtendedValidity:
    description: Allow import of certificates with validity greater than 398 days (required).
    type: bool
  allowOutOfDateCert:
    description: Allow out of date certificates (required).
    type: bool
  allowPortalTagTransferForSameSubject:
    description: Allow overwriting the portal tag from matching certificate of same
      subject.
    type: bool
  allowReplacementOfCertificates:
    description: Allow Replacement of certificates (required).
    type: bool
  allowReplacementOfPortalGroupTag:
    description: Allow Replacement of Portal Group Tag (required).
    type: bool
  allowRoleTransferForSameSubject:
    description: Allow transfer of roles for certificate with matching subject.
    type: bool
  allowSHA1Certificates:
    description: Allow SHA1 based certificates (required).
    type: bool
  allowWildCardCertificates:
    description: Allow Wildcard certificates.
    type: bool
  data:
    description: Certificate Content (required).
    type: str
  eap:
    description: Use certificate for EAP protocols that use SSL/TLS tunneling.
    type: bool
  ims:
    description: Use certificate for the Cisco ISE Messaging Service.
    type: bool
  name:
    description: Name of the certificate.
    type: str
  password:
    description: Certificate Password (required).
    type: str
  portal:
    description: Use for portal.
    type: bool
  portalGroupTag:
    description: Set Group tag.
    type: str
  privateKeyData:
    description: Private Key data (required).
    type: str
  pxgrid:
    description: Use certificate for the pxGrid Controller.
    type: bool
  radius:
    description: Use certificate for the RADSec server.
    type: bool
  saml:
    description: Use certificate for SAML Signing.
    type: bool
  validateCertificateExtensions:
    description: Validate certificate extensions.
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
    certificates.Certificates.import_system_certificate,

  - Paths used are
    post /api/v1/certs/system-certificate/import,

"""

EXAMPLES = r"""
- name: Create
  cisco.ise.system_certificate_import:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    admin: true
    allowExtendedValidity: true
    allowOutOfDateCert: true
    allowPortalTagTransferForSameSubject: true
    allowReplacementOfCertificates: true
    allowReplacementOfPortalGroupTag: true
    allowRoleTransferForSameSubject: true
    allowSHA1Certificates: true
    allowWildCardCertificates: true
    data: string
    eap: true
    ims: true
    name: string
    password: string
    portal: true
    portalGroupTag: string
    privateKeyData: string
    pxgrid: true
    radius: true
    saml: true
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

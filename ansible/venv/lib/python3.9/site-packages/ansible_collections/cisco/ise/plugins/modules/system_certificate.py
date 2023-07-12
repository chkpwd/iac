#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: system_certificate
short_description: Resource module for System Certificate
description:
- Manage operations update and delete of the resource System Certificate.
- This API deletes a System Certificate of a particular node based on given HostName and ID.
- Update a System Certificate.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  admin:
    description: Use certificate to authenticate the Cisco ISE Admin Portal.
    type: bool
  allowPortalTagTransferForSameSubject:
    description: Allow overwriting the portal tag from matching certificate of same
      subject.
    type: bool
  allowReplacementOfPortalGroupTag:
    description: Allow Replacement of Portal Group Tag (required).
    type: bool
  allowRoleTransferForSameSubject:
    description: Allow transfer of roles for certificate with matching subject.
    type: bool
  allowWildcardDelete:
    description: If the given certificate to be deleted is a wildcard certificate, corresponding
      certificate gets deleted on rest of the nodes in the deployment as well.
    type: bool
  description:
    description: Description of System Certificate.
    type: str
  eap:
    description: Use certificate for EAP protocols that use SSL/TLS tunneling.
    type: bool
  expirationTTLPeriod:
    description: System Certificate's expirationTTLPeriod.
    type: int
  expirationTTLUnits:
    description: System Certificate's expirationTTLUnits.
    type: str
  hostName:
    description: HostName path parameter. Name of Host whose certificate needs to be
      updated.
    type: str
  id:
    description: Id path parameter. ID of the System Certificate to be updated.
    type: str
  ims:
    description: Use certificate for the Cisco ISE Messaging Service.
    type: bool
  name:
    description: Name of the certificate.
    type: str
  portal:
    description: Use for portal.
    type: bool
  portalGroupTag:
    description: Set Group tag.
    type: str
  pxgrid:
    description: Use certificate for the pxGrid Controller.
    type: bool
  radius:
    description: Use certificate for the RADSec server.
    type: bool
  renewSelfSignedCertificate:
    description: Renew Self-signed Certificate.
    type: bool
  saml:
    description: Use certificate for SAML Signing.
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
    certificates.Certificates.delete_system_certificate_by_id,
    certificates.Certificates.update_system_certificate,

  - Paths used are
    delete /api/v1/certs/system-certificate/{hostName}/{id},
    put /api/v1/certs/system-certificate/{hostName}/{id},

"""

EXAMPLES = r"""
- name: Update by id
  cisco.ise.system_certificate:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    admin: true
    allowPortalTagTransferForSameSubject: true
    allowReplacementOfPortalGroupTag: true
    allowRoleTransferForSameSubject: true
    description: string
    eap: true
    expirationTTLPeriod: 0
    expirationTTLUnits: string
    hostName: string
    id: string
    ims: true
    name: string
    portal: true
    portalGroupTag: string
    pxgrid: true
    radius: true
    renewSelfSignedCertificate: true
    saml: true

- name: Delete by id
  cisco.ise.system_certificate:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    allowWildcardDelete: true
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
      "expirationDate": "string",
      "friendlyName": "string",
      "groupTag": "string",
      "id": "string",
      "issuedBy": "string",
      "issuedTo": "string",
      "keySize": 0,
      "link": {
        "href": "string",
        "rel": "string",
        "type": "string"
      },
      "portalsUsingTheTag": "string",
      "selfSigned": true,
      "serialNumberDecimalFormat": "string",
      "sha256Fingerprint": "string",
      "signatureAlgorithm": "string",
      "usedBy": "string",
      "validFrom": "string"
    }

ise_update_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  version_added: '1.1.0'
  type: dict
  sample: >
    {
      "response": {
        "id": "string",
        "link": {
          "href": "string",
          "rel": "string",
          "type": "string"
        },
        "message": "string",
        "status": "string"
      },
      "version": "string"
    }
"""

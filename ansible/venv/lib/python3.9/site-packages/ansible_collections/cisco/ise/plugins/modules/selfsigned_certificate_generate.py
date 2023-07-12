#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: selfsigned_certificate_generate
short_description: Resource module for Selfsigned Certificate Generate
description:
- Manage operation create of the resource Selfsigned Certificate Generate.
- Generate Self-signed Certificate.
version_added: '2.1.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  admin:
    description: Use certificate to authenticate the Cisco ISE Admin Portal.
    type: bool
  allowExtendedValidity:
    description: Allow generation of self-signed certificate with validity greater than
      398 days.
    type: bool
  allowPortalTagTransferForSameSubject:
    description: Allow overwriting the portal tag from matching certificate of same
      subject.
    type: bool
  allowReplacementOfCertificates:
    description: Allow Replacement of certificates.
    type: bool
  allowReplacementOfPortalGroupTag:
    description: Allow Replacement of Portal Group Tag.
    type: bool
  allowRoleTransferForSameSubject:
    description: Allow transfer of roles for certificate with matching subject.
    type: bool
  allowSanDnsBadName:
    description: Allow usage of SAN DNS Bad name.
    type: bool
  allowSanDnsNonResolvable:
    description: Allow use of non resolvable Common Name or SAN Values.
    type: bool
  allowWildCardCertificates:
    description: Allow Wildcard Certificates.
    type: bool
  certificatePolicies:
    description: Certificate Policies.
    type: str
  digestType:
    description: Digest to sign with.
    type: str
  eap:
    description: Use certificate for EAP protocols that use SSL/TLS tunneling.
    type: bool
  expirationTTL:
    description: Certificate expiration value.
    type: int
  expirationTTLUnit:
    description: Certificate expiration unit.
    type: str
  hostName:
    description: Hostname of the Cisco ISE node in which self-signed certificate should
      be generated.
    type: str
  keyLength:
    description: Bit size of public key.
    type: str
  keyType:
    description: Algorithm to use for certificate public key creation.
    type: str
  name:
    description: Friendly name of the certificate.
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
  saml:
    description: Use certificate for SAML Signing.
    type: bool
  sanDNS:
    description: Array of SAN (Subject Alternative Name) DNS entries.
    elements: str
    type: list
  sanIP:
    description: Array of SAN IP entries.
    elements: str
    type: list
  sanURI:
    description: Array of SAN URI entries.
    elements: str
    type: list
  subjectCity:
    description: Certificate city or locality (L).
    type: str
  subjectCommonName:
    description: Certificate common name (CN).
    type: str
  subjectCountry:
    description: Certificate country (C).
    type: str
  subjectOrg:
    description: Certificate organization (O).
    type: str
  subjectOrgUnit:
    description: Certificate organizational unit (OU).
    type: str
  subjectState:
    description: Certificate state (ST).
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
    certificates.Certificates.generate_self_signed_certificate,

  - Paths used are
    post /api/v1/certs/system-certificate/generate-selfsigned-certificate,

"""

EXAMPLES = r"""
- name: Create
  cisco.ise.selfsigned_certificate_generate:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    admin: true
    allowExtendedValidity: true
    allowPortalTagTransferForSameSubject: true
    allowReplacementOfCertificates: true
    allowReplacementOfPortalGroupTag: true
    allowRoleTransferForSameSubject: true
    allowSanDnsBadName: true
    allowSanDnsNonResolvable: true
    allowWildCardCertificates: true
    certificatePolicies: string
    digestType: string
    eap: true
    expirationTTL: 0
    expirationTTLUnit: string
    hostName: string
    keyLength: string
    keyType: string
    name: string
    portal: true
    portalGroupTag: string
    pxgrid: true
    radius: true
    saml: true
    sanDNS:
    - string
    sanIP:
    - string
    sanURI:
    - string
    subjectCity: string
    subjectCommonName: string
    subjectCountry: string
    subjectOrg: string
    subjectOrgUnit: string
    subjectState: string

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

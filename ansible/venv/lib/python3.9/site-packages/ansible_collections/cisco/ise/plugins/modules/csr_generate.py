#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: csr_generate
short_description: Resource module for CSR Generate
description:
- Manage operation create of the resource CSR Generate.
- Generate a certificate signing request for Multi-Use, Admin, EAP.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  allowWildCardCert:
    description: AllowWildCardCert flag.
    type: bool
  certificatePolicies:
    description: CSR Generate's certificatePolicies.
    type: str
  digestType:
    description: CSR Generate's digestType.
    type: str
  hostnames:
    description: CSR Generate's hostnames.
    elements: str
    type: list
  keyLength:
    description: CSR Generate's keyLength.
    type: str
  keyType:
    description: CSR Generate's keyType.
    type: str
  portalGroupTag:
    description: CSR Generate's portalGroupTag.
    type: str
  sanDNS:
    description: CSR Generate's sanDNS.
    elements: str
    type: list
  sanDir:
    description: CSR Generate's sanDir.
    elements: str
    type: list
  sanIP:
    description: CSR Generate's sanIP.
    elements: str
    type: list
  sanURI:
    description: CSR Generate's sanURI.
    elements: str
    type: list
  subjectCity:
    description: CSR Generate's subjectCity.
    type: str
  subjectCommonName:
    description: CSR Generate's subjectCommonName.
    type: str
  subjectCountry:
    description: CSR Generate's subjectCountry.
    type: str
  subjectOrg:
    description: CSR Generate's subjectOrg.
    type: str
  subjectOrgUnit:
    description: CSR Generate's subjectOrgUnit.
    type: str
  subjectState:
    description: CSR Generate's subjectState.
    type: str
  usedFor:
    description: CSR Generate's usedFor.
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
    certificates.Certificates.generate_csr,

  - Paths used are
    post /api/v1/certs/certificate-signing-request,

"""

EXAMPLES = r"""
- name: Create
  cisco.ise.csr_generate:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    allowWildCardCert: true
    certificatePolicies: string
    digestType: string
    hostnames:
    - string
    keyLength: string
    keyType: string
    portalGroupTag: string
    sanDNS:
    - string
    sanDir:
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
    usedFor: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": [
        {
          "id": "string",
          "link": {
            "href": "string",
            "rel": "string",
            "type": "string"
          },
          "message": "string"
        }
      ],
      "version": "string"
    }
"""

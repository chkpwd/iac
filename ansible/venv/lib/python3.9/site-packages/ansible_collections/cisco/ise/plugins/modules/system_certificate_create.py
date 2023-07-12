#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: system_certificate_create
short_description: Resource module for System Certificate Create
description:
- Manage operation create of the resource System Certificate Create.
- This API allows the client to create a system certificate.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  ersLocalCertStub:
    description: Inputs for certificate creation.
    suboptions:
      allowWildcardCerts:
        description: System Certificate Create's allowWildcardCerts.
        type: str
      certificatePolicies:
        description: System Certificate Create's certificatePolicies.
        type: str
      certificateSanDns:
        description: System Certificate Create's certificateSanDns.
        type: str
      certificateSanIp:
        description: System Certificate Create's certificateSanIp.
        type: str
      certificateSanUri:
        description: System Certificate Create's certificateSanUri.
        type: str
      digest:
        description: System Certificate Create's digest.
        type: str
      ersSubjectStub:
        description: Subject data of certificate.
        suboptions:
          commonName:
            description: System Certificate Create's commonName.
            type: str
          countryName:
            description: System Certificate Create's countryName.
            type: str
          localityName:
            description: System Certificate Create's localityName.
            type: str
          organizationName:
            description: System Certificate Create's organizationName.
            type: str
          organizationalUnitName:
            description: System Certificate Create's organizationalUnitName.
            type: str
          stateOrProvinceName:
            description: System Certificate Create's stateOrProvinceName.
            type: str
        type: dict
      expirationTTL:
        description: System Certificate Create's expirationTTL.
        type: int
      friendlyName:
        description: System Certificate Create's friendlyName.
        type: str
      groupTagDD:
        description: System Certificate Create's groupTagDD.
        type: str
      keyLength:
        description: System Certificate Create's keyLength.
        type: str
      keyType:
        description: System Certificate Create's keyType.
        type: str
      samlCertificate:
        description: System Certificate Create's samlCertificate.
        type: str
      selectedExpirationTTLUnit:
        description: System Certificate Create's selectedExpirationTTLUnit.
        type: str
      xgridCertificate:
        description: System Certificate Create's xgridCertificate.
        type: str
    type: dict
  nodeId:
    description: NodeId of Cisco ISE application.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    system_certificate.SystemCertificate.create_system_certificate,

  - Paths used are
    post /ers/config/systemcertificate,

"""

EXAMPLES = r"""
- name: Create
  cisco.ise.system_certificate_create:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    ersLocalCertStub:
      allowWildcardCerts: string
      certificatePolicies: string
      certificateSanDns: string
      certificateSanIp: string
      certificateSanUri: string
      digest: string
      ersSubjectStub:
        commonName: string
        countryName: string
        localityName: string
        organizationName: string
        organizationalUnitName: string
        stateOrProvinceName: string
      expirationTTL: 0
      friendlyName: string
      groupTagDD: string
      keyLength: string
      keyType: string
      samlCertificate: string
      selectedExpirationTTLUnit: string
      xgridCertificate: string
    nodeId: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""

#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: allowed_protocols_info
short_description: Information module for Allowed Protocols
description:
- Get all Allowed Protocols.
- Get Allowed Protocols by id.
- Get Allowed Protocols by name.
- This API allows the client to get all the allowed protocols.
- This API allows the client to get an allowed protocol by ID.
- This API allows the client to get an allowed protocol by name.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options:
  name:
    description:
    - Name path parameter.
    type: str
  id:
    description:
    - Id path parameter.
    type: str
  page:
    description:
    - Page query parameter. Page number.
    type: int
  size:
    description:
    - Size query parameter. Number of objects returned per page.
    type: int
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    allowed_protocols.AllowedProtocols.get_allowed_protocol_by_id,
    allowed_protocols.AllowedProtocols.get_allowed_protocol_by_name,
    allowed_protocols.AllowedProtocols.get_allowed_protocols_generator,

  - Paths used are
    get /ers/config/allowedprotocols,
    get /ers/config/allowedprotocols/name/{name},
    get /ers/config/allowedprotocols/{id},

"""

EXAMPLES = r"""
- name: Get all Allowed Protocols
  cisco.ise.allowed_protocols_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    page: 1
    size: 20
  register: result

- name: Get Allowed Protocols by id
  cisco.ise.allowed_protocols_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    id: string
  register: result

- name: Get Allowed Protocols by name
  cisco.ise.allowed_protocols_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    name: string
  register: result

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "id": "string",
      "name": "string",
      "description": "string",
      "eapTls": {
        "allowEapTlsAuthOfExpiredCerts": true,
        "eapTlsEnableStatelessSessionResume": true,
        "eapTlsSessionTicketTtl": 0,
        "eapTlsSessionTicketTtlUnits": "string",
        "eapTlsSessionTicketPrecentage": 0
      },
      "peap": {
        "allowPeapEapMsChapV2": true,
        "allowPeapEapMsChapV2PwdChange": true,
        "allowPeapEapMsChapV2PwdChangeRetries": 0,
        "allowPeapEapGtc": true,
        "allowPeapEapGtcPwdChange": true,
        "allowPeapEapGtcPwdChangeRetries": 0,
        "allowPeapEapTls": true,
        "allowPeapEapTlsAuthOfExpiredCerts": true,
        "requireCryptobinding": true,
        "allowPeapV0": true
      },
      "eapFast": {
        "allowEapFastEapMsChapV2": true,
        "allowEapFastEapMsChapV2PwdChange": true,
        "allowEapFastEapMsChapV2PwdChangeRetries": 0,
        "allowEapFastEapGtc": true,
        "allowEapFastEapGtcPwdChange": true,
        "allowEapFastEapGtcPwdChangeRetries": 0,
        "allowEapFastEapTls": true,
        "allowEapFastEapTlsAuthOfExpiredCerts": true,
        "eapFastUsePacs": true,
        "eapFastUsePacsTunnelPacTtl": 0,
        "eapFastUsePacsTunnelPacTtlUnits": "string",
        "eapFastUsePacsUseProactivePacUpdatePrecentage": 0,
        "eapFastUsePacsAllowAnonymProvisioning": true,
        "eapFastUsePacsAllowAuthenProvisioning": true,
        "eapFastUsePacsReturnAccessAcceptAfterAuthenticatedProvisioning": true,
        "eapFastUsePacsAcceptClientCert": true,
        "eapFastUsePacsMachinePacTtl": 0,
        "eapFastUsePacsMachinePacTtlUnits": "string",
        "eapFastUsePacsAllowMachineAuthentication": true,
        "eapFastUsePacsStatelessSessionResume": true,
        "eapFastUsePacsAuthorizationPacTtl": 0,
        "eapFastUsePacsAuthorizationPacTtlUnits": "string",
        "eapFastDontUsePacsAcceptClientCert": true,
        "eapFastDontUsePacsAllowMachineAuthentication": true,
        "eapFastEnableEAPChaining": true
      },
      "eapTtls": {
        "eapTtlsPapAscii": true,
        "eapTtlsChap": true,
        "eapTtlsMsChapV1": true,
        "eapTtlsMsChapV2": true,
        "eapTtlsEapMd5": true,
        "eapTtlsEapMsChapV2": true,
        "eapTtlsEapMsChapV2PwdChange": true,
        "eapTtlsEapMsChapV2PwdChangeRetries": 0
      },
      "teap": {
        "allowTeapEapMsChapV2": true,
        "allowTeapEapMsChapV2PwdChange": true,
        "allowTeapEapMsChapV2PwdChangeRetries": 0,
        "allowTeapEapTls": true,
        "allowTeapEapTlsAuthOfExpiredCerts": true,
        "acceptClientCertDuringTunnelEst": true,
        "enableEapChaining": true,
        "allowDowngradeMsk": true
      },
      "processHostLookup": true,
      "allowPapAscii": true,
      "allowChap": true,
      "allowMsChapV1": true,
      "allowMsChapV2": true,
      "allowEapMd5": true,
      "allowLeap": true,
      "allowEapTls": true,
      "allowEapTtls": true,
      "allowEapFast": true,
      "allowPeap": true,
      "allowTeap": true,
      "allowPreferredEapProtocol": true,
      "preferredEapProtocol": "string",
      "eapTlsLBit": true,
      "allowWeakCiphersForEap": true,
      "requireMessageAuth": true,
      "link": {
        "rel": "string",
        "href": "string",
        "type": "string"
      }
    }

ise_responses:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  version_added: '1.1.0'
  type: list
  elements: dict
  sample: >
    [
      {
        "id": "string",
        "name": "string",
        "description": "string",
        "eapTls": {
          "allowEapTlsAuthOfExpiredCerts": true,
          "eapTlsEnableStatelessSessionResume": true,
          "eapTlsSessionTicketTtl": 0,
          "eapTlsSessionTicketTtlUnits": "string",
          "eapTlsSessionTicketPrecentage": 0
        },
        "peap": {
          "allowPeapEapMsChapV2": true,
          "allowPeapEapMsChapV2PwdChange": true,
          "allowPeapEapMsChapV2PwdChangeRetries": 0,
          "allowPeapEapGtc": true,
          "allowPeapEapGtcPwdChange": true,
          "allowPeapEapGtcPwdChangeRetries": 0,
          "allowPeapEapTls": true,
          "allowPeapEapTlsAuthOfExpiredCerts": true,
          "requireCryptobinding": true,
          "allowPeapV0": true
        },
        "eapFast": {
          "allowEapFastEapMsChapV2": true,
          "allowEapFastEapMsChapV2PwdChange": true,
          "allowEapFastEapMsChapV2PwdChangeRetries": 0,
          "allowEapFastEapGtc": true,
          "allowEapFastEapGtcPwdChange": true,
          "allowEapFastEapGtcPwdChangeRetries": 0,
          "allowEapFastEapTls": true,
          "allowEapFastEapTlsAuthOfExpiredCerts": true,
          "eapFastUsePacs": true,
          "eapFastUsePacsTunnelPacTtl": 0,
          "eapFastUsePacsTunnelPacTtlUnits": "string",
          "eapFastUsePacsUseProactivePacUpdatePrecentage": 0,
          "eapFastUsePacsAllowAnonymProvisioning": true,
          "eapFastUsePacsAllowAuthenProvisioning": true,
          "eapFastUsePacsReturnAccessAcceptAfterAuthenticatedProvisioning": true,
          "eapFastUsePacsAcceptClientCert": true,
          "eapFastUsePacsMachinePacTtl": 0,
          "eapFastUsePacsMachinePacTtlUnits": "string",
          "eapFastUsePacsAllowMachineAuthentication": true,
          "eapFastUsePacsStatelessSessionResume": true,
          "eapFastUsePacsAuthorizationPacTtl": 0,
          "eapFastUsePacsAuthorizationPacTtlUnits": "string",
          "eapFastDontUsePacsAcceptClientCert": true,
          "eapFastDontUsePacsAllowMachineAuthentication": true,
          "eapFastEnableEAPChaining": true
        },
        "eapTtls": {
          "eapTtlsPapAscii": true,
          "eapTtlsChap": true,
          "eapTtlsMsChapV1": true,
          "eapTtlsMsChapV2": true,
          "eapTtlsEapMd5": true,
          "eapTtlsEapMsChapV2": true,
          "eapTtlsEapMsChapV2PwdChange": true,
          "eapTtlsEapMsChapV2PwdChangeRetries": 0
        },
        "teap": {
          "allowTeapEapMsChapV2": true,
          "allowTeapEapMsChapV2PwdChange": true,
          "allowTeapEapMsChapV2PwdChangeRetries": 0,
          "allowTeapEapTls": true,
          "allowTeapEapTlsAuthOfExpiredCerts": true,
          "acceptClientCertDuringTunnelEst": true,
          "enableEapChaining": true,
          "allowDowngradeMsk": true
        },
        "processHostLookup": true,
        "allowPapAscii": true,
        "allowChap": true,
        "allowMsChapV1": true,
        "allowMsChapV2": true,
        "allowEapMd5": true,
        "allowLeap": true,
        "allowEapTls": true,
        "allowEapTtls": true,
        "allowEapFast": true,
        "allowPeap": true,
        "allowTeap": true,
        "allowPreferredEapProtocol": true,
        "preferredEapProtocol": "string",
        "eapTlsLBit": true,
        "allowWeakCiphersForEap": true,
        "requireMessageAuth": true,
        "link": {
          "rel": "string",
          "href": "string",
          "type": "string"
        }
      }
    ]
"""

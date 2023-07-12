#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: allowed_protocols
short_description: Resource module for Allowed Protocols
description:
- Manage operations create, update and delete of the resource Allowed Protocols.
- This API creates an allowed protocol.
- This API deletes an allowed protocol.
- This API allows the client to update an allowed protocol.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  allowChap:
    description: AllowChap flag.
    type: bool
  allowEapFast:
    description: AllowEapFast flag.
    type: bool
  allowEapMd5:
    description: AllowEapMd5 flag.
    type: bool
  allowEapTls:
    description: AllowEapTls flag.
    type: bool
  allowEapTtls:
    description: AllowEapTtls flag.
    type: bool
  allowLeap:
    description: AllowLeap flag.
    type: bool
  allowMsChapV1:
    description: AllowMsChapV1 flag.
    type: bool
  allowMsChapV2:
    description: AllowMsChapV2 flag.
    type: bool
  allowPapAscii:
    description: AllowPapAscii flag.
    type: bool
  allowPeap:
    description: AllowPeap flag.
    type: bool
  allowPreferredEapProtocol:
    description: AllowPreferredEapProtocol flag.
    type: bool
  allowTeap:
    description: AllowTeap flag.
    type: bool
  allowWeakCiphersForEap:
    description: AllowWeakCiphersForEap flag.
    type: bool
  description:
    description: Allowed Protocols's description.
    type: str
  eapFast:
    description: The eapFast is required only if allowEapFast is true, otherwise it
      must be ignored. The object eapFast contains the settings for EAP FAST protocol.
    suboptions:
      allowEapFastEapGtc:
        description: AllowEapFastEapGtc flag.
        type: bool
      allowEapFastEapGtcPwdChange:
        description: The allowEapFastEapGtcPwdChange is required only if allowEapFastEapGtc
          is true, otherwise it must be ignored.
        type: bool
      allowEapFastEapGtcPwdChangeRetries:
        description: The allowEapFastEapGtcPwdChangeRetries is required only if allowEapFastEapGtc
          is true, otherwise it must be ignored. Valid range is 0-3.
        type: int
      allowEapFastEapMsChapV2:
        description: AllowEapFastEapMsChapV2 flag.
        type: bool
      allowEapFastEapMsChapV2PwdChange:
        description: The allowEapFastEapMsChapV2PwdChange is required only if allowEapFastEapMsChapV2
          is true, otherwise it must be ignored.
        type: bool
      allowEapFastEapMsChapV2PwdChangeRetries:
        description: The allowEapFastEapMsChapV2PwdChangeRetries is required only if
          eapTtlsEapMsChapV2 is true, otherwise it must be ignored. Valid range is 0-3.
        type: int
      allowEapFastEapTls:
        description: AllowEapFastEapTls flag.
        type: bool
      allowEapFastEapTlsAuthOfExpiredCerts:
        description: The allowEapFastEapTlsAuthOfExpiredCerts is required only if allowEapFastEapTls
          is true, otherwise it must be ignored.
        type: bool
      eapFastDontUsePacsAcceptClientCert:
        description: The eapFastDontUsePacsAcceptClientCert is required only if eapFastUsePacs
          is FALSE, otherwise it must be ignored.
        type: bool
      eapFastDontUsePacsAllowMachineAuthentication:
        description: The eapFastDontUsePacsAllowMachineAuthentication is required only
          if eapFastUsePacs is FALSE, otherwise it must be ignored.
        type: bool
      eapFastEnableEAPChaining:
        description: EapFastEnableEAPChaining flag.
        type: bool
      eapFastUsePacs:
        description: EapFastUsePacs flag.
        type: bool
      eapFastUsePacsAcceptClientCert:
        description: The eapFastUsePacsAcceptClientCert is required only if eapFastUsePacsAllowAuthenProvisioning
          is true, otherwise it must be ignored.
        type: bool
      eapFastUsePacsAllowAnonymProvisioning:
        description: The eapFastUsePacsAllowAnonymProvisioning is required only if eapFastUsePacs
          is true, otherwise it must be ignored.
        type: bool
      eapFastUsePacsAllowAuthenProvisioning:
        description: The eapFastUsePacsAllowAuthenProvisioning is required only if eapFastUsePacs
          is true, otherwise it must be ignored.
        type: bool
      eapFastUsePacsAllowMachineAuthentication:
        description: EapFastUsePacsAllowMachineAuthentication flag.
        type: bool
      eapFastUsePacsAuthorizationPacTtl:
        description: The eapFastUsePacsAuthorizationPacTtl is required only if eapFastUsePacsStatelessSessionResume
          is true, otherwise it must be ignored.
        type: int
      eapFastUsePacsAuthorizationPacTtlUnits:
        description: The eapFastUsePacsAuthorizationPacTtlUnits is required only if
          eapFastUsePacsStatelessSessionResume is true, otherwise it must be ignored.
          Allowed Values - SECONDS, - MINUTES, - HOURS, - DAYS, - WEEKS.
        type: str
      eapFastUsePacsMachinePacTtl:
        description: The eapFastUsePacsMachinePacTtl is required only if eapFastUsePacsAllowMachineAuthentication
          is true, otherwise it must be ignored.
        type: int
      eapFastUsePacsMachinePacTtlUnits:
        description: The eapFastUsePacsMachinePacTtlUnits is required only if eapFastUsePacsAllowMachineAuthentication
          is true, otherwise it must be ignored. Allowed Values - SECONDS, - MINUTES,
          - HOURS, - DAYS, - WEEKS.
        type: str
      eapFastUsePacsReturnAccessAcceptAfterAuthenticatedProvisioning:
        description: The eapFastUsePacsReturnAccessAcceptAfterAuthenticatedProvisioning
          is required only if eapFastUsePacsAllowAuthenProvisioning is true, otherwise
          it must be ignored.
        type: bool
      eapFastUsePacsStatelessSessionResume:
        description: The eapFastUsePacsStatelessSessionResume is required only if eapFastUsePacs
          is true, otherwise it must be ignored.
        type: bool
      eapFastUsePacsTunnelPacTtl:
        description: The eapFastUsePacsTunnelPacTtl is required only if eapFastUsePacs
          is true, otherwise it must be ignored.
        type: int
      eapFastUsePacsTunnelPacTtlUnits:
        description: The eapFastUsePacsTunnelPacTtlUnits is required only if eapFastUsePacs
          is true, otherwise it must be ignored. Allowed Values - SECONDS, - MINUTES,
          - HOURS, - DAYS, - WEEKS.
        type: str
      eapFastUsePacsUseProactivePacUpdatePrecentage:
        description: The eapFastUsePacsUseProactivePacUpdatePrecentage is required only
          if eapFastUsePacs is true, otherwise it must be ignored.
        type: int
    type: dict
  eapTls:
    description: The eapTls is required only if allowEapTls is true, otherwise it must
      be ignored. The object eapTls contains the settings for EAP TLS protocol.
    suboptions:
      allowEapTlsAuthOfExpiredCerts:
        description: AllowEapTlsAuthOfExpiredCerts flag.
        type: bool
      eapTlsEnableStatelessSessionResume:
        description: EapTlsEnableStatelessSessionResume flag.
        type: bool
      eapTlsSessionTicketPrecentage:
        description: The eapTlsSessionTicketPrecentage is required only if eapTlsEnableStatelessSessionResume
          is true, otherwise it must be ignored.
        type: int
      eapTlsSessionTicketTtl:
        description: Time to live. The eapTlsSessionTicketTtl is required only if eapTlsEnableStatelessSessionResume
          is true, otherwise it must be ignored.
        type: int
      eapTlsSessionTicketTtlUnits:
        description: Time to live time units. The eapTlsSessionTicketTtlUnits is required
          only if eapTlsEnableStatelessSessionResume is true, otherwise it must be ignored.
          Allowed Values - SECONDS, - MINUTES, - HOURS, - DAYS, - WEEKS.
        type: str
    type: dict
  eapTlsLBit:
    description: EapTlsLBit flag.
    type: bool
  eapTtls:
    description: The eapTtls is required only if allowEapTtls is true, otherwise it
      must be ignored. The object eapTtls contains the settings for EAP TTLS protocol.
    suboptions:
      eapTtlsChap:
        description: EapTtlsChap flag.
        type: bool
      eapTtlsEapMd5:
        description: EapTtlsEapMd5 flag.
        type: bool
      eapTtlsEapMsChapV2:
        description: EapTtlsEapMsChapV2 flag.
        type: bool
      eapTtlsEapMsChapV2PwdChange:
        description: The eapTtlsEapMsChapV2PwdChange is required only if eapTtlsEapMsChapV2
          is true, otherwise it must be ignored.
        type: bool
      eapTtlsEapMsChapV2PwdChangeRetries:
        description: The eapTtlsEapMsChapV2PwdChangeRetries is required only if eapTtlsEapMsChapV2
          is true, otherwise it must be ignored. Valid range is 0-3.
        type: int
      eapTtlsMsChapV1:
        description: EapTtlsMsChapV1 flag.
        type: bool
      eapTtlsMsChapV2:
        description: EapTtlsMsChapV2 flag.
        type: bool
      eapTtlsPapAscii:
        description: EapTtlsPapAscii flag.
        type: bool
    type: dict
  id:
    description: Resource UUID, Mandatory for update.
    type: str
  name:
    description: Resource Name.
    type: str
  peap:
    description: Allowed Protocols's peap.
    suboptions:
      allowPeapEapGtc:
        description: AllowPeapEapGtc flag.
        type: bool
      allowPeapEapGtcPwdChange:
        description: The allowPeapEapGtcPwdChange is required only if allowPeapEapGtc
          is true, otherwise it must be ignored.
        type: bool
      allowPeapEapGtcPwdChangeRetries:
        description: The allowPeapEapGtcPwdChangeRetries is required only if allowPeapEapGtc
          is true, otherwise it must be ignored. Valid range is 0-3.
        type: int
      allowPeapEapMsChapV2:
        description: AllowPeapEapMsChapV2 flag.
        type: bool
      allowPeapEapMsChapV2PwdChange:
        description: The allowPeapEapMsChapV2PwdChange is required only if allowPeapEapMsChapV2
          is true, otherwise it must be ignored.
        type: bool
      allowPeapEapMsChapV2PwdChangeRetries:
        description: The allowPeapEapMsChapV2PwdChangeRetries is required only if allowPeapEapMsChapV2
          is true, otherwise it must be ignored. Valid range is 0-3.
        type: int
      allowPeapEapTls:
        description: AllowPeapEapTls flag.
        type: bool
      allowPeapEapTlsAuthOfExpiredCerts:
        description: The allowPeapEapTlsAuthOfExpiredCerts is required only if allowPeapEapTls
          is true, otherwise it must be ignored.
        type: bool
      allowPeapV0:
        description: AllowPeapV0 flag.
        type: bool
      requireCryptobinding:
        description: RequireCryptobinding flag.
        type: bool
    type: dict
  preferredEapProtocol:
    description: The preferredEapProtocol is required only if allowPreferredEapProtocol
      is true, otherwise it must be ignored. Allowed Values - EAP_FAST, - PEAP, - LEAP,
      - EAP_MD5, - EAP_TLS, - EAP_TTLS, - TEAP.
    type: str
  processHostLookup:
    description: ProcessHostLookup flag.
    type: bool
  requireMessageAuth:
    description: RequireMessageAuth flag.
    type: bool
  teap:
    description: The teap is required only if allowTeap is true, otherwise it must be
      ignored. The object teap contains the settings for TEAP protocol.
    suboptions:
      acceptClientCertDuringTunnelEst:
        description: AcceptClientCertDuringTunnelEst flag.
        type: bool
      allowDowngradeMsk:
        description: AllowDowngradeMsk flag.
        type: bool
      allowTeapEapMsChapV2:
        description: AllowTeapEapMsChapV2 flag.
        type: bool
      allowTeapEapMsChapV2PwdChange:
        description: The allowTeapEapMsChapV2PwdChange is required only if allowTeapEapMsChapV2
          is true, otherwise it must be ignored.
        type: bool
      allowTeapEapMsChapV2PwdChangeRetries:
        description: The allowTeapEapMsChapV2PwdChangeRetries is required only if allowTeapEapMsChapV2
          is true, otherwise it must be ignored. Valid range is 0-3.
        type: int
      allowTeapEapTls:
        description: AllowTeapEapTls flag.
        type: bool
      allowTeapEapTlsAuthOfExpiredCerts:
        description: The allowTeapEapTlsAuthOfExpiredCerts is required only if allowTeapEapTls
          is true, otherwise it must be ignored.
        type: bool
      enableEapChaining:
        description: EnableEapChaining flag.
        type: bool
    type: dict
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    allowed_protocols.AllowedProtocols.create_allowed_protocol,
    allowed_protocols.AllowedProtocols.delete_allowed_protocol_by_id,
    allowed_protocols.AllowedProtocols.update_allowed_protocol_by_id,

  - Paths used are
    post /ers/config/allowedprotocols,
    delete /ers/config/allowedprotocols/{id},
    put /ers/config/allowedprotocols/{id},

"""

EXAMPLES = r"""
- name: Update by id
  cisco.ise.allowed_protocols:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    allowChap: true
    allowEapFast: true
    allowEapMd5: true
    allowEapTls: true
    allowEapTtls: true
    allowLeap: true
    allowMsChapV1: true
    allowMsChapV2: true
    allowPapAscii: true
    allowPeap: true
    allowPreferredEapProtocol: true
    allowTeap: true
    allowWeakCiphersForEap: true
    description: string
    eapFast:
      allowEapFastEapGtc: true
      allowEapFastEapGtcPwdChange: true
      allowEapFastEapGtcPwdChangeRetries: 0
      allowEapFastEapMsChapV2: true
      allowEapFastEapMsChapV2PwdChange: true
      allowEapFastEapMsChapV2PwdChangeRetries: 0
      allowEapFastEapTls: true
      allowEapFastEapTlsAuthOfExpiredCerts: true
      eapFastDontUsePacsAcceptClientCert: true
      eapFastDontUsePacsAllowMachineAuthentication: true
      eapFastEnableEAPChaining: true
      eapFastUsePacs: true
      eapFastUsePacsAcceptClientCert: true
      eapFastUsePacsAllowAnonymProvisioning: true
      eapFastUsePacsAllowAuthenProvisioning: true
      eapFastUsePacsAllowMachineAuthentication: true
      eapFastUsePacsAuthorizationPacTtl: 0
      eapFastUsePacsAuthorizationPacTtlUnits: string
      eapFastUsePacsMachinePacTtl: 0
      eapFastUsePacsMachinePacTtlUnits: string
      eapFastUsePacsReturnAccessAcceptAfterAuthenticatedProvisioning: true
      eapFastUsePacsStatelessSessionResume: true
      eapFastUsePacsTunnelPacTtl: 0
      eapFastUsePacsTunnelPacTtlUnits: string
      eapFastUsePacsUseProactivePacUpdatePrecentage: 0
    eapTls:
      allowEapTlsAuthOfExpiredCerts: true
      eapTlsEnableStatelessSessionResume: true
      eapTlsSessionTicketPrecentage: 0
      eapTlsSessionTicketTtl: 0
      eapTlsSessionTicketTtlUnits: string
    eapTlsLBit: true
    eapTtls:
      eapTtlsChap: true
      eapTtlsEapMd5: true
      eapTtlsEapMsChapV2: true
      eapTtlsEapMsChapV2PwdChange: true
      eapTtlsEapMsChapV2PwdChangeRetries: 0
      eapTtlsMsChapV1: true
      eapTtlsMsChapV2: true
      eapTtlsPapAscii: true
    id: string
    name: string
    peap:
      allowPeapEapGtc: true
      allowPeapEapGtcPwdChange: true
      allowPeapEapGtcPwdChangeRetries: 0
      allowPeapEapMsChapV2: true
      allowPeapEapMsChapV2PwdChange: true
      allowPeapEapMsChapV2PwdChangeRetries: 0
      allowPeapEapTls: true
      allowPeapEapTlsAuthOfExpiredCerts: true
      allowPeapV0: true
      requireCryptobinding: true
    preferredEapProtocol: string
    processHostLookup: true
    requireMessageAuth: true
    teap:
      acceptClientCertDuringTunnelEst: true
      allowDowngradeMsk: true
      allowTeapEapMsChapV2: true
      allowTeapEapMsChapV2PwdChange: true
      allowTeapEapMsChapV2PwdChangeRetries: 0
      allowTeapEapTls: true
      allowTeapEapTlsAuthOfExpiredCerts: true
      enableEapChaining: true

- name: Delete by id
  cisco.ise.allowed_protocols:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    id: string

- name: Create
  cisco.ise.allowed_protocols:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    allowChap: true
    allowEapFast: true
    allowEapMd5: true
    allowEapTls: true
    allowEapTtls: true
    allowLeap: true
    allowMsChapV1: true
    allowMsChapV2: true
    allowPapAscii: true
    allowPeap: true
    allowPreferredEapProtocol: true
    allowTeap: true
    allowWeakCiphersForEap: true
    description: string
    eapFast:
      allowEapFastEapGtc: true
      allowEapFastEapGtcPwdChange: true
      allowEapFastEapGtcPwdChangeRetries: 0
      allowEapFastEapMsChapV2: true
      allowEapFastEapMsChapV2PwdChange: true
      allowEapFastEapMsChapV2PwdChangeRetries: 0
      allowEapFastEapTls: true
      allowEapFastEapTlsAuthOfExpiredCerts: true
      eapFastDontUsePacsAcceptClientCert: true
      eapFastDontUsePacsAllowMachineAuthentication: true
      eapFastEnableEAPChaining: true
      eapFastUsePacs: true
      eapFastUsePacsAcceptClientCert: true
      eapFastUsePacsAllowAnonymProvisioning: true
      eapFastUsePacsAllowAuthenProvisioning: true
      eapFastUsePacsAllowMachineAuthentication: true
      eapFastUsePacsAuthorizationPacTtl: 0
      eapFastUsePacsAuthorizationPacTtlUnits: string
      eapFastUsePacsMachinePacTtl: 0
      eapFastUsePacsMachinePacTtlUnits: string
      eapFastUsePacsReturnAccessAcceptAfterAuthenticatedProvisioning: true
      eapFastUsePacsStatelessSessionResume: true
      eapFastUsePacsTunnelPacTtl: 0
      eapFastUsePacsTunnelPacTtlUnits: string
      eapFastUsePacsUseProactivePacUpdatePrecentage: 0
    eapTls:
      allowEapTlsAuthOfExpiredCerts: true
      eapTlsEnableStatelessSessionResume: true
      eapTlsSessionTicketPrecentage: 0
      eapTlsSessionTicketTtl: 0
      eapTlsSessionTicketTtlUnits: string
    eapTlsLBit: true
    eapTtls:
      eapTtlsChap: true
      eapTtlsEapMd5: true
      eapTtlsEapMsChapV2: true
      eapTtlsEapMsChapV2PwdChange: true
      eapTtlsEapMsChapV2PwdChangeRetries: 0
      eapTtlsMsChapV1: true
      eapTtlsMsChapV2: true
      eapTtlsPapAscii: true
    name: string
    peap:
      allowPeapEapGtc: true
      allowPeapEapGtcPwdChange: true
      allowPeapEapGtcPwdChangeRetries: 0
      allowPeapEapMsChapV2: true
      allowPeapEapMsChapV2PwdChange: true
      allowPeapEapMsChapV2PwdChangeRetries: 0
      allowPeapEapTls: true
      allowPeapEapTlsAuthOfExpiredCerts: true
      allowPeapV0: true
      requireCryptobinding: true
    preferredEapProtocol: string
    processHostLookup: true
    requireMessageAuth: true
    teap:
      acceptClientCertDuringTunnelEst: true
      allowDowngradeMsk: true
      allowTeapEapMsChapV2: true
      allowTeapEapMsChapV2PwdChange: true
      allowTeapEapMsChapV2PwdChangeRetries: 0
      allowTeapEapTls: true
      allowTeapEapTlsAuthOfExpiredCerts: true
      enableEapChaining: true

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

ise_update_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  version_added: '1.1.0'
  type: dict
  sample: >
    {
      "UpdatedFieldsList": {
        "updatedField": [
          {
            "field": "string",
            "oldValue": "string",
            "newValue": "string"
          }
        ],
        "field": "string",
        "oldValue": "string",
        "newValue": "string"
      }
    }
"""

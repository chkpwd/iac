#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: active_directory_add_groups
short_description: Resource module for Active Directory Add Groups
description:
- Manage operation update of the resource Active Directory Add Groups.
- This API loads domain groups configuration from Active Directory into Cisco.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  adAttributes:
    description: Holds list of AD Attributes.
    suboptions:
      attributes:
        description: List of Attributes.
        elements: dict
        suboptions:
          defaultValue:
            description: Required for each attribute in the attribute list. Can contain
              an empty string. All characters are allowed except <%".
            type: str
          internalName:
            description: Required for each attribute in the attribute list. All characters
              are allowed except <%".
            type: str
          name:
            description: Required for each attribute in the attribute list with no duplication
              between attributes. All characters are allowed except <%".
            type: str
          type:
            description: Required for each group in the group list. Allowed values STRING,
              IP, BOOLEAN, INT, OCTET_STRING.
            type: str
        type: list
    type: dict
  adScopesNames:
    description: String that contains the names of the scopes that the active directory
      belongs to. Names are separated by comma. Alphanumeric, underscore (_) characters
      are allowed.
    type: str
  adgroups:
    description: Holds list of AD Groups.
    suboptions:
      groups:
        description: List of Groups.
        elements: dict
        suboptions:
          name:
            description: Required for each group in the group list with no duplication
              between groups. All characters are allowed except %.
            type: str
          sid:
            description: Cisco ISE uses security identifiers (SIDs) for optimization
              of group membership evaluation. SIDs are useful for efficiency (speed)
              when the groups are evaluated. All characters are allowed except %.
            type: str
          type:
            description: No character restriction.
            type: str
        type: list
    type: dict
  advancedSettings:
    description: Active Directory Add Groups's advancedSettings.
    suboptions:
      agingTime:
        description: Range 1-8760 hours.
        type: int
      authProtectionType:
        description: Enable prevent AD account lockout. Allowed values - WIRELESS, -
          WIRED, - BOTH.
        type: str
      country:
        description: User info attribute. All characters are allowed except %.
        type: str
      department:
        description: User info attribute. All characters are allowed except %.
        type: str
      email:
        description: User info attribute. All characters are allowed except %.
        type: str
      enableCallbackForDialinClient:
        description: EnableCallbackForDialinClient flag.
        type: bool
      enableDialinPermissionCheck:
        description: EnableDialinPermissionCheck flag.
        type: bool
      enableFailedAuthProtection:
        description: Enable prevent AD account lockout due to too many bad password
          attempts.
        type: bool
      enableMachineAccess:
        description: EnableMachineAccess flag.
        type: bool
      enableMachineAuth:
        description: EnableMachineAuth flag.
        type: bool
      enablePassChange:
        description: EnablePassChange flag.
        type: bool
      enableRewrites:
        description: EnableRewrites flag.
        type: bool
      failedAuthThreshold:
        description: Number of bad password attempts.
        type: int
      firstName:
        description: User info attribute. All characters are allowed except %.
        type: str
      identityNotInAdBehaviour:
        description: Allowed values REJECT, SEARCH_JOINED_FOREST, SEARCH_ALL.
        type: str
      jobTitle:
        description: User info attribute. All characters are allowed except %.
        type: str
      lastName:
        description: User info attribute. All characters are allowed except %.
        type: str
      locality:
        description: User info attribute. All characters are allowed except %.
        type: str
      organizationalUnit:
        description: User info attribute. All characters are allowed except %.
        type: str
      plaintextAuth:
        description: PlaintextAuth flag.
        type: bool
      rewriteRules:
        description: Identity rewrite is an advanced feature that directs Cisco ISE
          to manipulate the identity before it is passed to the external Active Directory
          system. You can create rules to change the identity to a desired format that
          includes or excludes a domain prefix and/or suffix or other additional markup
          of your choice.
        elements: dict
        suboptions:
          rewriteMatch:
            description: Required for each rule in the list with no duplication between
              rules. All characters are allowed except %".
            type: str
          rewriteResult:
            description: Required for each rule in the list. All characters are allowed
              except %".
            type: str
          rowId:
            description: Required for each rule in the list in serial order.
            type: int
        type: list
      schema:
        description: Allowed values ACTIVE_DIRECTORY, CUSTOM. Choose ACTIVE_DIRECTORY
          schema when the AD attributes defined in AD can be copied to relevant attributes
          in Cisco ISE. If customization is needed, choose CUSTOM schema. All User info
          attributes are always set to default value if schema is ACTIVE_DIRECTORY.
          Values can be changed only for CUSTOM schema.
        type: str
      stateOrProvince:
        description: User info attribute. All characters are allowed except %.
        type: str
      streetAddress:
        description: User info attribute. All characters are allowed except %.
        type: str
      telephone:
        description: User info attribute. All characters are allowed except %.
        type: str
      unreachableDomainsBehaviour:
        description: Allowed values PROCEED, DROP.
        type: str
    type: dict
  description:
    description: No character restriction.
    type: str
  domain:
    description: The AD domain. Alphanumeric, hyphen (-) and dot (.) characters are
      allowed.
    type: str
  enableDomainWhiteList:
    description: EnableDomainWhiteList flag.
    type: bool
  id:
    description: Resource UUID value.
    type: str
  name:
    description: Resource Name. Maximum 32 characters allowed. Allowed characters are
      alphanumeric and .-_/\\ characters.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    active_directory.ActiveDirectory.load_groups_from_domain,

  - Paths used are
    put /ers/config/activedirectory/{id}/addGroups,

"""

EXAMPLES = r"""
- name: Update all
  cisco.ise.active_directory_add_groups:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    adAttributes:
      attributes:
      - defaultValue: string
        internalName: string
        name: string
        type: string
    adScopesNames: string
    adgroups:
      groups:
      - name: string
        sid: string
        type: string
    advancedSettings:
      agingTime: 0
      authProtectionType: string
      country: string
      department: string
      email: string
      enableCallbackForDialinClient: true
      enableDialinPermissionCheck: true
      enableFailedAuthProtection: true
      enableMachineAccess: true
      enableMachineAuth: true
      enablePassChange: true
      enableRewrites: true
      failedAuthThreshold: 0
      firstName: string
      identityNotInAdBehaviour: string
      jobTitle: string
      lastName: string
      locality: string
      organizationalUnit: string
      plaintextAuth: true
      rewriteRules:
      - rewriteMatch: string
        rewriteResult: string
        rowId: 0
      schema: string
      stateOrProvince: string
      streetAddress: string
      telephone: string
      unreachableDomainsBehaviour: string
    description: string
    domain: string
    enableDomainWhiteList: true
    id: string
    name: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""

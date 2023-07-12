#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: support_bundle
short_description: Resource module for Support Bundle
description:
- Manage operation create of the resource Support Bundle.
- This API allows the client to create a support bundle trigger configuration.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  description:
    description: Support Bundle's description.
    type: str
  hostName:
    description: This parameter is hostName only, xxxx of xxxx.yyy.zz.
    type: str
  name:
    description: Resource Name.
    type: str
  supportBundleIncludeOptions:
    description: Support Bundle's supportBundleIncludeOptions.
    suboptions:
      fromDate:
        description: Date from where support bundle should include the logs.
        type: str
      includeConfigDB:
        description: Set to include Config DB in Support Bundle.
        type: bool
      includeCoreFiles:
        description: Set to include Core files in Support Bundle.
        type: bool
      includeDebugLogs:
        description: Set to include Debug logs in Support Bundle.
        type: bool
      includeLocalLogs:
        description: Set to include Local logs in Support Bundle.
        type: bool
      includeSystemLogs:
        description: Set to include System logs in Support Bundle.
        type: bool
      mntLogs:
        description: Set to include Monitoring and troublshooting logs in Support Bundle.
        type: bool
      policyXml:
        description: Set to include Policy XML in Support Bundle.
        type: bool
      toDate:
        description: Date upto where support bundle should include the logs.
        type: str
    type: dict
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for SupportBundleTriggerConfiguration
  description: Complete reference of the SupportBundleTriggerConfiguration API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!supportbundle
notes:
  - SDK Method used are
    support_bundle_trigger_configuration.SupportBundleTriggerConfiguration.create_support_bundle,

  - Paths used are
    post /ers/config/supportbundle,

"""

EXAMPLES = r"""
- name: Create
  cisco.ise.support_bundle:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    description: string
    hostName: string
    name: string
    supportBundleIncludeOptions:
      fromDate: string
      includeConfigDB: true
      includeCoreFiles: true
      includeDebugLogs: true
      includeLocalLogs: true
      includeSystemLogs: true
      mntLogs: true
      policyXml: true
      toDate: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""

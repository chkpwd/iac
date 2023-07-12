#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: backup_last_status_info
short_description: Information module for Backup Last Status
description:
- Get all Backup Last Status.
- Gives the last backup status.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options: {}
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for Backup And Restore
  description: Complete reference of the Backup And Restore API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!backup-and-restore-open-api
notes:
  - SDK Method used are
    backup_and_restore.BackupAndRestore.get_last_config_backup_status,

  - Paths used are
    get /api/v1/backup-restore/config/last-backup-status,

"""

EXAMPLES = r"""
- name: Get all Backup Last Status
  cisco.ise.backup_last_status_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
  register: result

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "action": "string",
      "details": "string",
      "error": "string",
      "hostName": "string",
      "initiatedFrom": "string",
      "justComplete": "string",
      "message": "string",
      "name": "string",
      "percentComplete": "string",
      "repository": "string",
      "scheduled": "string",
      "startDate": "string",
      "status": "string",
      "type": "string"
    }
"""

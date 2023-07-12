#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: backup_restore
short_description: Resource module for Backup RESTore
description:
- Manage operation create of the resource Backup RESTore.
- Triggers a configuration DB restore job on the ISE node. The API returns the task ID. Use the Task Service status API to get the status of the backup job.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  backupEncryptionKey:
    description: The encryption key which was provided at the time of taking backup.
    type: str
  repositoryName:
    description: Name of the configred repository where the backup file exists.
    type: str
  restoreFile:
    description: Name of the backup file to be restored on ISE node.
    type: str
  restoreIncludeAdeos:
    description: Determines whether the ADE-OS configure is restored. Possible values
      true, false.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for Backup And Restore
  description: Complete reference of the Backup And Restore API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!backup-and-restore-open-api
notes:
  - SDK Method used are
    backup_and_restore.BackupAndRestore.restore_config_backup,

  - Paths used are
    post /api/v1/backup-restore/config/restore,

"""

EXAMPLES = r"""
- name: Create
  cisco.ise.backup_restore:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    backupEncryptionKey: string
    repositoryName: string
    restoreFile: string
    restoreIncludeAdeos: string

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
        "link": {
          "rel": "string",
          "href": "string",
          "type": "string"
        }
      },
      "version": "string"
    }
"""

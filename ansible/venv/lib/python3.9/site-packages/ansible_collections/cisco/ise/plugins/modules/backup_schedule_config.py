#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: backup_schedule_config
short_description: Resource module for Backup Schedule Config
description:
- Manage operation create of the resource Backup Schedule Config.
- Schedules the configuration backup on the ISE node as per the input parameters. This API helps in creating the schedule for the first time.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  backupDescription:
    description: Description of the backup.
    type: str
  backupEncryptionKey:
    description: The encyption key for the backed up file. Encryption key must satisfy
      the following criteria - Contains at least one uppercase letter A-Z, Contains
      at least one lowercase letter a-z, Contains at least one digit 0-9, Contain only
      A-Za-z0-9_#, Has at least 8 characters, Has not more than 15 characters, Must
      not contain 'CcIiSsCco', Must not begin with.
    type: str
  backupName:
    description: The backup file will get saved with this name.
    type: str
  endDate:
    description: End date of the scheduled backup job. Allowed format MM/DD/YYYY. End
      date is not required in case of ONE_TIME frequency.
    type: str
  frequency:
    description: Backup Schedule Config's frequency.
    type: str
  monthDay:
    description: Day of month you want backup to be performed on when scheduled frequency
      is MONTHLY. Allowed values - from 1 to 28.
    type: str
  repositoryName:
    description: Name of the configured repository where the generated backup file will
      get copied.
    type: str
  startDate:
    description: Start date for scheduling the backup job. Allowed format MM/DD/YYYY.
    type: str
  status:
    description: Backup Schedule Config's status.
    type: str
  time:
    description: Time at which backup job get scheduled. Example- 12 00 AM.
    type: str
  weekDay:
    description: Backup Schedule Config's weekDay.
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
    backup_and_restore.BackupAndRestore.create_scheduled_config_backup,

  - Paths used are
    post /api/v1/backup-restore/config/schedule-config-backup,

"""

EXAMPLES = r"""
- name: Create
  cisco.ise.backup_schedule_config:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    backupDescription: string
    backupEncryptionKey: string
    backupName: string
    endDate: string
    frequency: string
    monthDay: string
    repositoryName: string
    startDate: string
    status: string
    time: string
    weekDay: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
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

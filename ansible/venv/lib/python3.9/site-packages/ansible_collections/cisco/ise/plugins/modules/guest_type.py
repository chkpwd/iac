#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: guest_type
short_description: Resource module for Guest Type
description:
- Manage operations create, update and delete of the resource Guest Type.
- This API creates a guest type.
- This API deletes a guest type.
- This API allows the client to update a guest type.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  accessTime:
    description: Guest Type's accessTime.
    suboptions:
      allowAccessOnSpecificDaysTimes:
        description: AllowAccessOnSpecificDaysTimes flag.
        type: bool
      dayTimeLimits:
        description: List of Time Ranges for account access.
        elements: dict
        suboptions:
          days:
            description: List of Days Values should be one of Week day. Allowed values
              are - Sunday, - Monday, - Tuesday, - Wednesday, - Thursday, - Friday,
              - Saturday.
            elements: str
            type: list
          endTime:
            description: End time in HH mm format.
            type: str
          startTime:
            description: Start time in HH mm format.
            type: str
        type: list
      defaultDuration:
        description: Guest Type's defaultDuration.
        type: int
      durationTimeUnit:
        description: Allowed values are - DAYS, - HOURS, - MINUTES.
        type: str
      fromFirstLogin:
        description: When Account Duration starts from first login or specified date.
        type: bool
      maxAccountDuration:
        description: Maximum value of Account Duration.
        type: int
    type: dict
  description:
    description: Guest Type's description.
    type: str
  expirationNotification:
    description: Expiration Notification Settings.
    suboptions:
      advanceNotificationDuration:
        description: Send Account Expiration Notification Duration before ( Days, Hours,
          Minutes ).
        type: int
      advanceNotificationUnits:
        description: Allowed values are - DAYS, - HOURS, - MINUTES.
        type: str
      emailText:
        description: Guest Type's emailText.
        type: str
      enableNotification:
        description: Enable Notification settings.
        type: bool
      sendEmailNotification:
        description: Enable Email Notification.
        type: bool
      sendSMSNotification:
        description: Maximum devices guests can register.
        type: bool
      smsText:
        description: Guest Type's smsText.
        type: str
    type: dict
  id:
    description: Guest Type's id.
    type: str
  isDefaultType:
    description: IsDefaultType flag.
    type: bool
  loginOptions:
    description: Guest Type's loginOptions.
    suboptions:
      allowGuestPortalBypass:
        description: AllowGuestPortalBypass flag.
        type: bool
      failureAction:
        description: When Guest Exceeds limit this action will be invoked. Allowed values
          are - Disconnect_Oldest_Connection, - Disconnect_Newest_Connection.
        type: str
      identityGroupId:
        description: Guest Type's identityGroupId.
        type: str
      limitSimultaneousLogins:
        description: Enable Simultaneous Logins.
        type: bool
      maxRegisteredDevices:
        description: Maximum devices guests can register.
        type: int
      maxSimultaneousLogins:
        description: Number of Simultaneous Logins.
        type: int
    type: dict
  name:
    description: Guest Type's name.
    type: str
  sponsorGroups:
    description: Guest Type's sponsorGroups.
    elements: str
    type: list
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    guest_type.GuestType.create_guest_type,
    guest_type.GuestType.delete_guest_type_by_id,
    guest_type.GuestType.update_guest_type_by_id,

  - Paths used are
    post /ers/config/guesttype,
    delete /ers/config/guesttype/{id},
    put /ers/config/guesttype/{id},

"""

EXAMPLES = r"""
- name: Update by id
  cisco.ise.guest_type:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    accessTime:
      allowAccessOnSpecificDaysTimes: true
      dayTimeLimits:
      - days:
        - string
        endTime: string
        startTime: string
      defaultDuration: 0
      durationTimeUnit: string
      fromFirstLogin: true
      maxAccountDuration: 0
    description: string
    expirationNotification:
      advanceNotificationDuration: 0
      advanceNotificationUnits: string
      emailText: string
      enableNotification: true
      sendEmailNotification: true
      sendSmsNotification: true
      smsText: string
    id: string
    isDefaultType: true
    loginOptions:
      allowGuestPortalBypass: true
      failureAction: string
      identityGroupId: string
      limitSimultaneousLogins: true
      maxRegisteredDevices: 0
      maxSimultaneousLogins: 0
    name: string
    sponsorGroups:
    - string

- name: Delete by id
  cisco.ise.guest_type:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    id: string

- name: Create
  cisco.ise.guest_type:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    accessTime:
      allowAccessOnSpecificDaysTimes: true
      dayTimeLimits:
      - days:
        - string
        endTime: string
        startTime: string
      defaultDuration: 0
      durationTimeUnit: string
      fromFirstLogin: true
      maxAccountDuration: 0
    description: string
    expirationNotification:
      advanceNotificationDuration: 0
      advanceNotificationUnits: string
      emailText: string
      enableNotification: true
      sendEmailNotification: true
      sendSmsNotification: true
      smsText: string
    isDefaultType: true
    loginOptions:
      allowGuestPortalBypass: true
      failureAction: string
      identityGroupId: string
      limitSimultaneousLogins: true
      maxRegisteredDevices: 0
      maxSimultaneousLogins: 0
    name: string
    sponsorGroups:
    - string

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
      "isDefaultType": true,
      "accessTime": {
        "fromFirstLogin": true,
        "maxAccountDuration": 0,
        "durationTimeUnit": "string",
        "defaultDuration": 0,
        "allowAccessOnSpecificDaysTimes": true,
        "dayTimeLimits": [
          {
            "startTime": "string",
            "endTime": "string",
            "days": [
              "string"
            ]
          }
        ]
      },
      "loginOptions": {
        "limitSimultaneousLogins": true,
        "maxSimultaneousLogins": 0,
        "failureAction": "string",
        "maxRegisteredDevices": 0,
        "identityGroupId": "string",
        "allowGuestPortalBypass": true
      },
      "expirationNotification": {
        "enableNotification": true,
        "advanceNotificationDuration": 0,
        "advanceNotificationUnits": "string",
        "sendEmailNotification": true,
        "emailText": "string",
        "sendSmsNotification": true,
        "smsText": "string"
      },
      "sponsorGroups": [
        "string"
      ],
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

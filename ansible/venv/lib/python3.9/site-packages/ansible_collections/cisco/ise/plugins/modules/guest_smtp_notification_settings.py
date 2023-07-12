#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: guest_smtp_notification_settings
short_description: Resource module for Guest SMTP Notification Settings
description:
- Manage operations create and update of the resource Guest SMTP Notification Settings.
- This API creates a guest SMTP notification configuration.
- This API allows the client to update a SMTP configuration setting.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  connectionTimeout:
    description: Interval in seconds for all the SMTP client connections.
    type: str
  defaultFromAddress:
    description: The default from email address to be used to send emails from.
    type: str
  id:
    description: Guest SMTP Notification Settings's id.
    type: str
  notificationEnabled:
    description: Indicates if the email notification service is to be enabled.
    type: bool
  password:
    description: Password of Secure SMTP server.
    type: str
  smtpPort:
    description: Port at which SMTP Secure Server is listening.
    type: str
  smtpServer:
    description: The SMTP server ip address or fqdn such as outbound.mycompany.com.
    type: str
  useDefaultFromAddress:
    description: If the default from address should be used rather than using a sponsor
      user email address.
    type: bool
  usePasswordAuthentication:
    description: If configured to true, SMTP server authentication will happen using
      username/password.
    type: bool
  useTLSorSSLEncryption:
    description: If configured to true, SMTP server authentication will happen using
      TLS/SSL.
    type: bool
  userName:
    description: Username of Secure SMTP server.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    guest_smtp_notification_configuration.GuestSmtpNotificationConfiguration.create_guest_smtp_notification_settings,
    guest_smtp_notification_configuration.GuestSmtpNotificationConfiguration.update_guest_smtp_notification_settings_by_id,

  - Paths used are
    post /ers/config/guestsmtpnotificationsettings,
    put /ers/config/guestsmtpnotificationsettings/{id},

"""

EXAMPLES = r"""
- name: Update by id
  cisco.ise.guest_smtp_notification_settings:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    connectionTimeout: string
    defaultFromAddress: string
    id: string
    notificationEnabled: true
    password: string
    smtpPort: string
    smtpServer: string
    useDefaultFromAddress: true
    usePasswordAuthentication: true
    useTLSorSSLEncryption: true
    userName: string

- name: Create
  cisco.ise.guest_smtp_notification_settings:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    connectionTimeout: string
    defaultFromAddress: string
    notificationEnabled: true
    password: string
    smtpPort: string
    smtpServer: string
    useDefaultFromAddress: true
    usePasswordAuthentication: true
    useTLSorSSLEncryption: true
    userName: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "id": "string",
      "smtpServer": "string",
      "notificationEnabled": true,
      "useDefaultFromAddress": true,
      "defaultFromAddress": "string",
      "smtpPort": "string",
      "connectionTimeout": "string",
      "useTLSorSSLEncryption": true,
      "usePasswordAuthentication": true,
      "userName": "string",
      "password": "string",
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

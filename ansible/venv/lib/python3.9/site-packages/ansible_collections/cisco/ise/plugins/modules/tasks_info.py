#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: tasks_info
short_description: Information module for Tasks
description:
- Get all Tasks.
- Get Tasks by id.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options:
  taskId:
    description:
    - TaskId path parameter. The id of the task executed before.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for tasks
  description: Complete reference of the tasks API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!task-service-openapi
notes:
  - SDK Method used are
    tasks.Tasks.get_task_status,
    tasks.Tasks.get_task_status_by_id,

  - Paths used are
    get /api/v1/task,
    get /api/v1/task/{taskId},

"""

EXAMPLES = r"""
- name: Get all Tasks
  cisco.ise.tasks_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
  register: result

- name: Get Tasks by id
  cisco.ise.tasks_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    taskId: string
  register: result

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "detailStatus": [
        {}
      ],
      "executionStatus": "string",
      "failCount": 0,
      "id": "string",
      "moduleType": "string",
      "resourcesCount": 0,
      "startTime": "string",
      "successCount": 0
    }
"""

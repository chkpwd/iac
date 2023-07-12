#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2018, Yanis Guenane <yanis+ansible@guenane.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


DOCUMENTATION = r'''
---
module: vultr_startup_script_info
short_description: Gather information about the Vultr startup scripts available.
description:
  - Gather information about vultr_startup_scripts available.
version_added: "0.1.0"
author: "Yanis Guenane (@Spredzy)"
extends_documentation_fragment:
- ngine_io.vultr.vultr

'''

EXAMPLES = r'''
- name: Gather Vultr startup scripts information
  ngine_io.vultr.vultr_startup_script_info:
  register: result

- name: Print the gathered information
  debug:
    var: result.vultr_startup_script_info
'''

RETURN = r'''
---
vultr_api:
  description: Response from Vultr API with a few additions/modification
  returned: success
  type: complex
  contains:
    api_account:
      description: Account used in the ini file to select the key
      returned: success
      type: str
      sample: default
    api_timeout:
      description: Timeout used for the API requests
      returned: success
      type: int
      sample: 60
    api_retries:
      description: Amount of max retries for the API requests
      returned: success
      type: int
      sample: 5
    api_retry_max_delay:
      description: Exponential backoff delay in seconds between retries up to this max delay value.
      returned: success
      type: int
      sample: 12
    api_endpoint:
      description: Endpoint used for the API requests
      returned: success
      type: str
      sample: "https://api.vultr.com"
vultr_startup_script_info:
  description: Response from Vultr API
  returned: success
  type: complex
  contains:
    id:
      description: ID of the startup script.
      returned: success
      type: str
      sample: 249395
    name:
      description: Name of the startup script.
      returned: success
      type: str
      sample: my startup script
    script:
      description: The source code of the startup script.
      returned: success
      type: str
      sample: "#!/bin/bash\necho Hello World > /root/hello"
    type:
      description: The type of the startup script.
      returned: success
      type: str
      sample: pxe
    date_created:
      description: Date the startup script was created.
      returned: success
      type: str
      sample: "2017-08-26 12:47:48"
    date_modified:
      description: Date the startup script was modified.
      returned: success
      type: str
      sample: "2017-08-26 12:47:48"
'''

from ansible.module_utils.basic import AnsibleModule
from ..module_utils.vultr import (
    Vultr,
    vultr_argument_spec,
)


class AnsibleVultrStartupScriptInfo(Vultr):

    def __init__(self, module):
        super(AnsibleVultrStartupScriptInfo, self).__init__(module, "vultr_startup_script_info")

        self.returns = {
            "SCRIPTID": dict(key='id', convert_to='int'),
            "date_created": dict(),
            "date_modified": dict(),
            "name": dict(),
            "script": dict(),
            "type": dict(),
        }

    def get_startupscripts(self):
        return self.api_query(path="/v1/startupscript/list")


def parse_startupscript_list(startupscipts_list):
    if not startupscipts_list:
        return []

    return [startupscript for id, startupscript in startupscipts_list.items()]


def main():
    argument_spec = vultr_argument_spec()

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    startupscript_info = AnsibleVultrStartupScriptInfo(module)
    result = startupscript_info.get_result(parse_startupscript_list(startupscript_info.get_startupscripts()))
    module.exit_json(**result)


if __name__ == '__main__':
    main()

#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Paul Arthur <paul.arthur@flowerysong.com>
# Copyright: (c) 2019, XLAB Steampunk <steampunk@xlab.si>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["stableinterface"],
    "supported_by": "certified",
}

DOCUMENTATION = '''
module: check_info
author:
  - Paul Arthur (@flowerysong)
  - Aljaz Kosir (@aljazkosir)
  - Miha Plesko (@miha-plesko)
  - Tadej Borovsak (@tadeboro)
short_description: List Sensu checks
description:
  - Retrieve information about Sensu Go checks.
  - For more information, refer to the Sensu documentation at
    U(https://docs.sensu.io/sensu-go/latest/reference/checks/).
version_added: 1.0.0
extends_documentation_fragment:
  - sensu.sensu_go.requirements
  - sensu.sensu_go.auth
  - sensu.sensu_go.info
  - sensu.sensu_go.namespace
seealso:
  - module: sensu.sensu_go.check
'''

EXAMPLES = '''
- name: List all Sensu checks
  sensu.sensu_go.check_info:
  register: result

- name: Obtain a specific check
  sensu.sensu_go.check_info:
    name: my-check
  register: result
'''

RETURN = '''
objects:
  description: List of Sensu checks.
  returned: success
  type: list
  elements: dict
  sample:
    - metadata:
        name: check_minimum
        namespace: default
      command: collect.sh
      handlers:
        - slack
      interval: 10
      publish: true
      subscriptions:
        - system
'''

from ansible.module_utils.basic import AnsibleModule

from ..module_utils import arguments, errors, utils


def main():
    module = AnsibleModule(
        supports_check_mode=True,
        argument_spec=dict(
            arguments.get_spec("auth", "namespace"),
            name=dict(),  # Name is not required in info modules.
        ),
    )

    client = arguments.get_sensu_client(module.params["auth"])
    path = utils.build_core_v2_path(
        module.params["namespace"], "checks", module.params["name"],
    )

    try:
        checks = utils.prepare_result_list(utils.get(client, path))
    except errors.Error as e:
        module.fail_json(msg=str(e))

    module.exit_json(changed=False, objects=checks)


if __name__ == '__main__':
    main()

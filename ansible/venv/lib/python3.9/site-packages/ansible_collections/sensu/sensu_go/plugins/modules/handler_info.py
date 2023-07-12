#!/usr/bin/python
# -*- coding: utf-8 -*-
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
module: handler_info
author:
  - Aljaz Kosir (@aljazkosir)
  - Miha Plesko (@miha-plesko)
  - Tadej Borovsak (@tadeboro)
short_description: List Sensu handlers
description:
  - Retrieve information about Sensu handlers.
  - For more information, refer to the Sensu documentation at
    U(https://docs.sensu.io/sensu-go/latest/reference/handlers/).
version_added: 1.0.0
extends_documentation_fragment:
  - sensu.sensu_go.requirements
  - sensu.sensu_go.auth
  - sensu.sensu_go.info
  - sensu.sensu_go.namespace
seealso:
  - module: sensu.sensu_go.socket_handler
  - module: sensu.sensu_go.pipe_handler
  - module: sensu.sensu_go.handler_set
'''

EXAMPLES = '''
- name: List all Sensu handlers
  sensu.sensu_go.handler_info:
  register: result

- name: Retrieve info for a specific Sensu handler
  sensu.sensu_go.handler_info:
    name: my-handler
  register: result
'''

RETURN = '''
objects:
  description: List of Sensu handlers.
  returned: success
  type: list
  elements: dict
  sample:
    - metadata:
        name: tcp_udp_handler_minimum
        namespace: default
      socket:
        host: 10.0.1.99
        port: 4444
      type: tcp
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
        module.params["namespace"], "handlers", module.params["name"],
    )

    try:
        handlers = utils.prepare_result_list(utils.get(client, path))
    except errors.Error as e:
        module.fail_json(msg=str(e))

    module.exit_json(changed=False, objects=handlers)


if __name__ == '__main__':
    main()

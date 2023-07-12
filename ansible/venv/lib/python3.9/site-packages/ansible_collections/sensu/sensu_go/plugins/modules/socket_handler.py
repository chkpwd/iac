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
module: socket_handler
author:
  - Aljaz Kosir (@aljazkosir)
  - Miha Plesko (@miha-plesko)
  - Tadej Borovsak (@tadeboro)
short_description: Manage Sensu TCP/UDP handler
description:
  - Create, update or delete Sensu socket handler.
  - For more information, refer to the Sensu documentation at
    U(https://docs.sensu.io/sensu-go/latest/reference/handlers/#tcp-udp-handlers).
version_added: 1.0.0
extends_documentation_fragment:
  - sensu.sensu_go.requirements
  - sensu.sensu_go.auth
  - sensu.sensu_go.name
  - sensu.sensu_go.namespace
  - sensu.sensu_go.state
  - sensu.sensu_go.labels
  - sensu.sensu_go.annotations
seealso:
  - module: sensu.sensu_go.handler_info
  - module: sensu.sensu_go.pipe_handler
  - module: sensu.sensu_go.handler_set
options:
  type:
    description:
      - The handler type.
      - Required if I(state) is C(present).
    choices:
      - tcp
      - udp
    type: str
  filters:
    description:
      - List of filters to use when determining whether to pass the check result to this handler.
    type: list
    elements: str
  mutator:
    description:
      - Mutator to call for transforming the check result before passing it to this handler.
    type: str
  timeout:
    description:
      - Timeout for handler execution.
    type: int
  host:
    description:
      - The socket host address (IP or hostname) to connect to.
      - Required if I(state) is C(present).
    type: str
  port:
    description:
      - The socket port to connect to.
      - Required if I(state) is C(present).
    type: int
'''

EXAMPLES = '''
- name: TCP handler
  sensu.sensu_go.socket_handler:
    name: tcp_handler
    type: tcp
    host: 10.0.1.99
    port: 4444

- name: UDP handler
  sensu.sensu_go.socket_handler:
    name: udp_handler
    type: udp
    host: 10.0.1.99
    port: 4444

- name: Delete a handler
  sensu.sensu_go.socket_handler:
    name: udp_handler
    state: absent
'''

RETURN = '''
object:
  description: Object representing Sensu socket handler.
  returned: success
  type: dict
  sample:
    - metadata:
        name: udp_handler
        namespace: default
      socket:
        host: 10.0.1.99
        port: 4444
      type: udp
'''

from ansible.module_utils.basic import AnsibleModule

from ..module_utils import arguments, errors, utils


def main():
    required_if = [
        ('state', 'present', ['type', 'host', 'port'])
    ]
    module = AnsibleModule(
        supports_check_mode=True,
        required_if=required_if,
        argument_spec=dict(
            arguments.get_spec(
                "auth", "name", "state", "labels", "annotations", "namespace",
            ),
            type=dict(choices=['tcp', 'udp']),
            filters=dict(
                type='list', elements='str',
            ),
            mutator=dict(),
            timeout=dict(
                type='int'
            ),
            host=dict(),
            port=dict(
                type='int'
            )
        ),
    )

    client = arguments.get_sensu_client(module.params['auth'])
    path = utils.build_core_v2_path(
        module.params['namespace'], 'handlers', module.params['name'],
    )
    payload = arguments.get_mutation_payload(
        module.params, 'type', 'filters', 'mutator', 'timeout'
    )
    payload['socket'] = dict(host=module.params['host'], port=module.params['port'])

    try:
        changed, handler = utils.sync(
            module.params['state'], client, path, payload, module.check_mode,
        )
        module.exit_json(changed=changed, object=handler)
    except errors.Error as e:
        module.fail_json(msg=str(e))


if __name__ == '__main__':
    main()

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
module: pipe_handler
author:
  - Aljaz Kosir (@aljazkosir)
  - Miha Plesko (@miha-plesko)
  - Tadej Borovsak (@tadeboro)
short_description: Manage Sensu pipe handler
description:
  - Create, update or delete a Sensu pipe handler.
  - For more information, refer to the Sensu documentation at
    U(https://docs.sensu.io/sensu-go/latest/reference/handlers/#pipe-handlers).
version_added: 1.0.0
extends_documentation_fragment:
  - sensu.sensu_go.requirements
  - sensu.sensu_go.auth
  - sensu.sensu_go.name
  - sensu.sensu_go.namespace
  - sensu.sensu_go.state
  - sensu.sensu_go.labels
  - sensu.sensu_go.annotations
  - sensu.sensu_go.secrets
seealso:
  - module: sensu.sensu_go.socket_handler
  - module: sensu.sensu_go.handler_info
  - module: sensu.sensu_go.handler_set
options:
  command:
    description:
      - The handler command to be executed. The event data is passed to the
        process through STDIN.
      - Required if I(state) is C(present).
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
  env_vars:
    description:
      - A mapping of environment variable names and values to use with command execution.
    type: dict
  runtime_assets:
    description:
      - List of runtime assets to required to run the handler C(command).
    type: list
    elements: str
'''

EXAMPLES = '''
- name: Setup InfluxDB handler
  sensu.sensu_go.pipe_handler:
    name: influx-db
    command: sensu-influxdb-handler -d sensu
    env_vars:
      INFLUXDB_ADDR: http://influxdb.default.svc.cluster.local:8086
      INFLUXDB_USER: sensu
      INFLUXDB_PASS: password
    runtime_assets:
      - sensu-influxdb-handler

- name: Delete  handler
  sensu.sensu_go.pipe_handler:
    name: influx-db
    state: absent
'''

RETURN = '''
object:
  description: Object representing Sensu pipe handler.
  returned: success
  type: dict
  sample:
    metadata:
      name: pipe_handler_minimum
      namespace: default
    command: command-example
    type: pipe
'''

from ansible.module_utils.basic import AnsibleModule

from ..module_utils import arguments, errors, utils


def do_differ(current, desired):
    return (
        utils.do_differ(current, desired, "secrets") or
        utils.do_secrets_differ(current, desired)
    )


def main():
    required_if = [
        ('state', 'present', ['command'])
    ]
    module = AnsibleModule(
        supports_check_mode=True,
        required_if=required_if,
        argument_spec=dict(
            arguments.get_spec(
                "auth", "name", "state", "labels", "annotations", "namespace",
                "secrets",
            ),
            command=dict(),
            filters=dict(
                type='list', elements='str',
            ),
            mutator=dict(),
            timeout=dict(
                type='int'
            ),
            env_vars=dict(
                type='dict'
            ),
            runtime_assets=dict(
                type='list', elements='str',
            ),
        ),
    )

    client = arguments.get_sensu_client(module.params['auth'])
    path = utils.build_core_v2_path(
        module.params['namespace'], 'handlers', module.params['name'],
    )
    payload = arguments.get_mutation_payload(
        module.params, 'command', 'filters', 'mutator', 'timeout',
        'runtime_assets', 'secrets',
    )
    payload['type'] = 'pipe'
    if module.params['env_vars']:
        payload['env_vars'] = utils.dict_to_key_value_strings(module.params['env_vars'])

    try:
        changed, handler = utils.sync(
            module.params['state'], client, path, payload, module.check_mode,
            do_differ,
        )
        module.exit_json(changed=changed, object=handler)
    except errors.Error as e:
        module.fail_json(msg=str(e))


if __name__ == '__main__':
    main()

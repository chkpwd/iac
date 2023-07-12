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
module: mutator
author:
  - Paul Arthur (@flowerysong)
  - Aljaz Kosir (@aljazkosir)
  - Miha Plesko (@miha-plesko)
  - Tadej Borovsak (@tadeboro)
short_description: Manage Sensu mutators
description:
  - Create, update or delete Sensu mutator.
  - For more information, refer to the Sensu documentation at
    U(https://docs.sensu.io/sensu-go/latest/reference/mutators/).
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
  - module: sensu.sensu_go.mutator_info
options:
  command:
    description:
      - The mutator command to be executed by the Sensu backend.
      - Required if I(state) is C(present).
    type: str
  timeout:
    description:
      - The mutator execution duration timeout in seconds (hard stop).
    type: int
  env_vars:
    description:
      - A mapping of environment variable names and values to use with command execution.
    type: dict
  runtime_assets:
    description:
      - List of runtime assets, required to run the mutator I(command).
    type: list
    elements: str
'''

EXAMPLES = '''
- name: Create a mutator
  sensu.sensu_go.mutator:
    name: mutator
    command: sensu-influxdb-mutator
    timeout: 30
    env_vars:
      INFLUXDB_ADDR: http://influxdb.default.svc.cluster.local:8086
      INFLUXDB_USER: sensu
    runtime_assets:
      - sensu-influxdb-mutator

- name: Delete a mutator
  sensu.sensu_go.mutator:
    name: mutator
    state: absent
'''

RETURN = '''
object:
  description: Object representing Sensu mutator.
  returned: success
  type: dict
  sample:
    metadata:
      annotations: null
      labels: null
      name: example-mutator
      namespace: default
    command: example_mutator.go
    env_vars: []
    runtime_assets: []
    timeout: 0
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
        required_if=required_if,
        supports_check_mode=True,
        argument_spec=dict(
            arguments.get_spec(
                "auth", "name", "state", "labels", "annotations", "namespace",
                "secrets",
            ),
            command=dict(),
            timeout=dict(
                type='int',
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
        module.params['namespace'], 'mutators', module.params['name'],
    )
    payload = arguments.get_mutation_payload(
        module.params, 'command', 'timeout', 'runtime_assets', 'secrets',
    )
    if module.params['env_vars']:
        payload['env_vars'] = utils.dict_to_key_value_strings(module.params['env_vars'])
    try:
        changed, mutator = utils.sync(
            module.params['state'], client, path, payload, module.check_mode,
            do_differ,
        )
        module.exit_json(changed=changed, object=mutator)
    except errors.Error as e:
        module.fail_json(msg=str(e))


if __name__ == '__main__':
    main()

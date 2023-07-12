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
module: hook
author:
  - Paul Arthur (@flowerysong)
  - Aljaz Kosir (@aljazkosir)
  - Miha Plesko (@miha-plesko)
  - Tadej Borovsak (@tadeboro)
short_description: Manage Sensu hooks
description:
  - Create, update or delete Sensu hook.
  - For more information, refer to the Sensu documentation at
    U(https://docs.sensu.io/sensu-go/latest/reference/hooks/).
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
  - module: sensu.sensu_go.hook_info
options:
  command:
    description:
      - Command to run when the hook is triggered.
      - Required if I(state) is C(present).
    type: str
  timeout:
    description:
      - The hook execution duration timeout in seconds (hard stop).
      - Required if I(state) is C(present).
    type: int
  stdin:
    description:
      - Controls whether Sensu writes serialized JSON data to the process's stdin.
    type: bool
  runtime_assets:
    description:
      - List of runtime assets required to run the check.
    type: list
    elements: str
'''

EXAMPLES = '''
- name: Rudimentary auto-remediation hook
  sensu.sensu_go.hook:
    auth:
      url: http://localhost:8080
    name: restart_nginx
    command: sudo systemctl start nginx
    timeout: 60
    stdin: false

- name: Capture the process tree
  sensu.sensu_go.hook:
    auth:
      url: http://localhost:8080
    name: process_tree
    command: ps aux
    timeout: 60
    stdin: false

- name: Delete a hook
  sensu.sensu_go.hook:
    name: process_tree
    state: absent
'''

RETURN = '''
object:
  description: Object representing Sensu hook.
  returned: success
  type: dict
  sample:
    metadata:
      annotations: null
      labels: null
      name: restart_nginx
      namespace: default
    command: sudo systemctl start nginx
    stdin: false
    timeout: 60
'''

from ansible.module_utils.basic import AnsibleModule

from ..module_utils import arguments, errors, utils


def main():
    required_if = [
        ('state', 'present', ['command', 'timeout'])
    ]
    module = AnsibleModule(
        required_if=required_if,
        supports_check_mode=True,
        argument_spec=dict(
            arguments.get_spec(
                "auth", "name", "state", "labels", "annotations", "namespace",
            ),
            command=dict(),
            timeout=dict(
                type='int',
            ),
            stdin=dict(
                type='bool'
            ),
            runtime_assets=dict(
                type='list', elements='str',
            ),
        ),
    )

    client = arguments.get_sensu_client(module.params['auth'])
    path = utils.build_core_v2_path(
        module.params['namespace'], 'hooks', module.params['name'],
    )
    payload = arguments.get_mutation_payload(
        module.params, 'command', 'timeout', 'stdin', 'runtime_assets'
    )
    try:
        changed, hook = utils.sync(
            module.params['state'], client, path, payload, module.check_mode,
        )
        module.exit_json(changed=changed, object=hook)
    except errors.Error as e:
        module.fail_json(msg=str(e))


if __name__ == '__main__':
    main()

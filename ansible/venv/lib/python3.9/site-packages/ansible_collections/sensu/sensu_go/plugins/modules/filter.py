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
module: filter
author:
  - Paul Arthur (@flowerysong)
  - Aljaz Kosir (@aljazkosir)
  - Miha Plesko (@miha-plesko)
  - Tadej Borovsak (@tadeboro)
short_description: Manage Sensu filters
description:
  - Create, update or delete Sensu filter.
  - For more information, refer to the Sensu documentation at
    U(https://docs.sensu.io/sensu-go/latest/reference/filters/).
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
  - module: sensu.sensu_go.filter_info
options:
  action:
    description:
      - Action to take with the event if the filter expressions match.
      - Required if I(state) is C(present).
    type: str
    choices: [ 'allow', 'deny' ]
  expressions:
    description:
      - Filter expressions to be compared with event data.
      - Required if I(state) is C(present).
    type: list
    elements: str
  runtime_assets:
    description:
      - Assets to be applied to the filter's execution context.
        JavaScript files in the lib directory of the asset will be evaluated.
    type: list
    elements: str
'''

EXAMPLES = '''
- name: Create a filter
  sensu.sensu_go.filter:
    name: filter
    action: deny
    expressions:
      - event.check.interval == 10
      - event.check.occurrences == 1
    runtime_assets: awesomeness

- name: Create a production filter
  sensu.sensu_go.filter:
    name: filter
    action: allow
    expressions:
      - event.entity.labels['environment'] == 'production'

- name: Create a filter with JS expression
  sensu.sensu_go.filter:
    name: filter
    action: deny
    expressions:
      - "_.reduce(event.check.history, function(memo, h) { return (memo || h.status != 0); })"
    runtime_assets:
      - underscore

- name: Handling repeated events
  sensu.sensu_go.filter:
    name: filter_interval_60_hourly
    action: allow
    expressions:
      - event.check.interval == 60
      - event.check.occurrences == 1 || event.check.occurrences % 60 == 0

- name: Delete a filter
  sensu.sensu_go.filter:
    name: filter_interval_60_hourly
    state: absent
'''

RETURN = '''
object:
  description: Object representing Sensu filter.
  returned: success
  type: dict
  sample:
    metadata:
      name: filter_minimum
      namespace: default
    action: allow
    expressions:
      - event.check.occurrences == 1
'''

from ansible.module_utils.basic import AnsibleModule

from ..module_utils import arguments, errors, utils


def main():
    required_if = [
        ('state', 'present', ['action', 'expressions'])
    ]
    module = AnsibleModule(
        required_if=required_if,
        supports_check_mode=True,
        argument_spec=dict(
            arguments.get_spec(
                "auth", "name", "state", "labels", "annotations", "namespace",
            ),
            action=dict(choices=['allow', 'deny']),
            expressions=dict(
                type='list', elements='str',
            ),
            runtime_assets=dict(
                type='list', elements='str',
            ),
        ),
    )

    client = arguments.get_sensu_client(module.params['auth'])
    path = utils.build_core_v2_path(
        module.params['namespace'], 'filters', module.params['name'],
    )
    payload = arguments.get_mutation_payload(
        module.params, 'action', 'expressions', 'runtime_assets'
    )
    try:
        changed, sensu_filter = utils.sync(
            module.params['state'], client, path, payload, module.check_mode,
        )
        module.exit_json(changed=changed, object=sensu_filter)
    except errors.Error as e:
        module.fail_json(msg=str(e))


if __name__ == '__main__':
    main()

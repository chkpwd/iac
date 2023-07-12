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
module: event
author:
  - Paul Arthur (@flowerysong)
  - Aljaz Kosir (@aljazkosir)
  - Manca Bizjak (@mancabizjak)
  - Tadej Borovsak (@tadeboro)
short_description: Manage Sensu events
description:
  - Send a synthetic event to Sensu.
  - For more information, refer to the Sensu documentation at
    U(https://docs.sensu.io/sensu-go/latest/reference/events/).
version_added: 1.0.0
extends_documentation_fragment:
  - sensu.sensu_go.requirements
  - sensu.sensu_go.auth
  - sensu.sensu_go.namespace
seealso:
  - module: sensu.sensu_go.event_info
notes:
  - Metric events bypass the store and are sent off to the event pipeline and corresponding event
    handlers. Read more about this at
    U(https://docs.sensu.io/sensu-go/latest/reference/events/#metric-only-events).
options:
  timestamp:
    description:
      - UNIX time at which the event occurred.
    type: int
  entity:
    description:
      - Name of the entity associated with this event. It must exist before event creation.
    type: str
    required: true
  check:
    description:
      - Name of the check associated with this event. It must exist before event creation.
    type: str
    required: true
  check_attributes:
    type: dict
    description:
      - Additional check parameters. Find out more at
        U(https://docs.sensu.io/sensu-go/latest/reference/events/#check-attributes).
    suboptions:
      duration:
        description:
          - Command execution time in seconds.
        type: float
      executed:
        description:
          - Time that the check request was executed.
        type: int
      history:
        description:
          - Check status history for the last 21 check executions.
        type: list
        elements: dict
      issued:
        description:
          - Time that the check request was issued in seconds since the Unix epoch.
        type: int
      last_ok:
        description:
          - The last time that the check returned an OK status (0) in seconds since the Unix epoch.
        type: int
      output:
        description:
          - The output from the execution of the check command.
        type: str
      state:
        description:
          - The state of the check.
        choices: [ "passing", "failing", "flapping" ]
        type: str
      status:
        description:
          - Exit status code produced by the check.
        choices: [ "ok", "warning", "critical", "unknown" ]
        type: str
      total_state_change:
        description:
          - The total state change percentage for the check's history.
        type: int
  metric_attributes:
    type: dict
    description:
      - Metric attributes. Find out more at
        U(https://docs.sensu.io/sensu-go/latest/reference/events/#metric-attributes).
    suboptions:
      handlers:
        description:
          - An array of Sensu handlers to use for events created by the check.
            Each array item must be a string.
        type: list
        elements: str
      points:
        description:
          - Metric data points including a name, timestamp, value, and tags.
        type: list
        elements: dict
'''

EXAMPLES = '''
- name: Create an event
  sensu.sensu_go.event:
    auth:
      url: http://localhost:8080
    entity: awesome_entity
    check: awesome_check
    check_attributes:
      duration: 1.945
      executed: 1522100915
      history:
        - executed: 1552505193
          status: 1
      issued: 1552506034
      last_ok: 1552506033
      output: '10'
      state: 'passing'
      status: 'ok'
      total_state_change: 0
    metric_attributes:
      handlers:
        - handler1
        - handler2
      points:
        - name: "sensu-go-sandbox.curl_timings.time_total"
          tags:
            - name: "response_time_in_ms"
              value: 101
          timestamp: 1552506033
          value: 0.005
        - name: "sensu-go-sandbox.curl_timings.time_namelookup"
          tags:
            - name: "namelookup_time_in_ms"
              value: 57
          timestamp: 1552506033
          value: 0.004
'''

RETURN = '''
object:
  description: Object representing Sensu event (deprecated).
  returned: success
  type: dict
  sample:
    metadata:
      namespace: default
    check:
      check_hooks: null
      command: check-cpu.sh -w 75 -c 90
      duration: 1.07055808
      env_vars: null
      executed: 1552594757
      handlers: []
      high_flap_threshold: 0
      history:
      - executed: 1552594757
        status: 0
      interval: 60
      metadata:
        name: check-cpu
        namespace: default
      occurrences: 1
      occurrences_watermark: 1
      output: CPU OK - Usage:3.96
      subscriptions:
        - linux
      timeout: 0
      total_state_change: 0
      ttl: 0
    entity:
      deregister: false
      deregistration: {}
      entity_class: agent
      last_seen: 1552594641
      metadata:
        name: sensu-centos
        namespace: default
    timestamp: 1552594758
    id: 3a5948f3-6ffd-4ea2-a41e-334f4a72ca2f
    sequence: 1
'''

from ansible.module_utils.basic import AnsibleModule

from ..module_utils import arguments, errors, utils

STATUS_MAP = {
    'ok': 0,
    'warning': 1,
    'critical': 2,
    'unknown': 3,
}


def get_check(client, namespace, check):
    check_path = utils.build_core_v2_path(namespace, 'checks', check)
    resp = client.get(check_path)
    if resp.status != 200:
        raise errors.SyncError("Check with name '{0}' does not exist on remote.".format(check))
    return resp.json


def get_entity(client, namespace, entity):
    entity_path = utils.build_core_v2_path(namespace, 'entities', entity)
    resp = client.get(entity_path)
    if resp.status != 200:
        raise errors.SyncError("Entity with name '{0}' does not exist on remote.".format(entity))
    return resp.json


def _update_payload_with_metric_attributes(payload, metric_attributes):
    if not metric_attributes:
        return

    payload['metrics'] = arguments.get_spec_payload(metric_attributes, *metric_attributes.keys())


def _update_payload_with_check_attributes(payload, check_attributes):
    if not check_attributes:
        return

    if check_attributes['status']:
        check_attributes['status'] = STATUS_MAP[check_attributes['status']]

    filtered_attributes = arguments.get_spec_payload(check_attributes, *check_attributes.keys())
    payload['check'].update(filtered_attributes)


def _build_api_payload(client, params):
    payload = arguments.get_spec_payload(params, 'timestamp')
    payload['metadata'] = dict(
        namespace=params['namespace']
    )
    payload['entity'] = get_entity(client, params['namespace'], params['entity'])
    payload['check'] = get_check(client, params['namespace'], params['check'])

    _update_payload_with_check_attributes(payload, params['check_attributes'])
    _update_payload_with_metric_attributes(payload, params['metric_attributes'])
    return payload


def send_event(client, path, payload, check_mode):
    if not check_mode:
        utils.put(client, path, payload)
    return True, payload


def main():
    module = AnsibleModule(
        supports_check_mode=True,
        argument_spec=dict(
            arguments.get_spec("auth", "namespace"),
            timestamp=dict(type='int'),
            entity=dict(required=True),
            check=dict(required=True),
            check_attributes=dict(
                type='dict',
                options=dict(
                    duration=dict(
                        type='float'
                    ),
                    executed=dict(
                        type='int'
                    ),
                    history=dict(
                        type='list', elements='dict',
                    ),
                    issued=dict(
                        type='int'
                    ),
                    last_ok=dict(
                        type='int'
                    ),
                    output=dict(),
                    state=dict(
                        choices=['passing', 'failing', 'flapping']
                    ),
                    status=dict(
                        choices=['ok', 'warning', 'critical', 'unknown']
                    ),
                    total_state_change=dict(
                        type='int'
                    )
                )
            ),
            metric_attributes=dict(
                type='dict',
                options=dict(
                    handlers=dict(
                        type='list',
                        elements='str'
                    ),
                    points=dict(
                        type='list',
                        elements='dict'
                    )
                )
            )
        )
    )

    client = arguments.get_sensu_client(module.params['auth'])
    path = utils.build_core_v2_path(
        module.params['namespace'], 'events', module.params['entity'],
        module.params['check'],
    )

    try:
        payload = _build_api_payload(client, module.params)
        changed, event = send_event(client, path, payload, module.check_mode)
        module.exit_json(changed=changed, object=event)
    except errors.Error as e:
        module.fail_json(msg=str(e))


if __name__ == '__main__':
    main()

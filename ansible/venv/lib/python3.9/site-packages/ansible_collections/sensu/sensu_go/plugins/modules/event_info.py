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
module: event_info
author:
  - Paul Arthur (@flowerysong)
  - Aljaz Kosir (@aljazkosir)
  - Manca Bizjak (@mancabizjak)
  - Tadej Borovsak (@tadeboro)
short_description: List Sensu events
description:
  - Retrieve recent events that Sensu processed.
  - For more information, refer to the Sensu documentation at
    U(https://docs.sensu.io/sensu-go/latest/reference/events/).
version_added: 1.0.0
extends_documentation_fragment:
  - sensu.sensu_go.requirements
  - sensu.sensu_go.auth
  - sensu.sensu_go.namespace
seealso:
  - module: sensu.sensu_go.event
options:
  check:
    description:
      - Limit results to a specific check.
      - I(entity) must also be specified if this parameter is used.
    type: str
  entity:
    description:
      - Limit results to a specific entity.
    type: str
'''

EXAMPLES = '''
- name: List Sensu events
  sensu.sensu_go.event_info:
  register: result

- name: List Sensu events for api.example.com
  sensu.sensu_go.event_info:
    entity: api.example.com
  register: result

- name: Filter events by check and entity
  sensu.sensu_go.event_info:
    entity: api.example.com
    check: check-cpu
  register: result
'''

RETURN = '''
objects:
  description: List of Sensu events.
  returned: success
  type: list
  elements: dict
  sample:
    - metadata:
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


def main():
    required_by = {'check': ['entity']}
    module = AnsibleModule(
        supports_check_mode=True,
        required_by=required_by,
        argument_spec=dict(
            arguments.get_spec("auth", "namespace"),
            check=dict(),
            entity=dict(),
        ),
    )

    client = arguments.get_sensu_client(module.params['auth'])
    path = utils.build_core_v2_path(
        module.params['namespace'], 'events', module.params['entity'],
        module.params['check'],
    )

    try:
        events = utils.prepare_result_list(utils.get(client, path))
    except errors.Error as e:
        module.fail_json(msg=str(e))

    module.exit_json(changed=False, objects=events)


if __name__ == '__main__':
    main()

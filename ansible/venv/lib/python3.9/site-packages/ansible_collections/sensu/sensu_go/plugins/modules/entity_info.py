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
module: entity_info
author:
  - Paul Arthur (@flowerysong)
  - Aljaz Kosir (@aljazkosir)
  - Miha Plesko (@miha-plesko)
  - Tadej Borovsak (@tadeboro)
short_description: List Sensu entities
description:
  - Retrieve information about Sensu entities.
  - For more information, refer to the Sensu documentation at
    U(https://docs.sensu.io/sensu-go/latest/reference/entities/).
version_added: 1.0.0
extends_documentation_fragment:
  - sensu.sensu_go.requirements
  - sensu.sensu_go.auth
  - sensu.sensu_go.info
  - sensu.sensu_go.namespace
seealso:
  - module: sensu.sensu_go.entity
'''

EXAMPLES = '''
- name: List all Sensu entities
  sensu.sensu_go.entity_info:
  register: result

- name: Retrieve a specific Sensu entity
  sensu.sensu_go.entity_info:
    name: my-entity
  register: result
'''

RETURN = '''
objects:
  description: List of Sensu entities.
  returned: success
  type: list
  elements: dict
  sample:
    - metadata:
        annotations: null
        labels: null
        name: webserver01
        namespace: default
      deregister: false
      deregistration: {}
      entity_class: agent
      last_seen: 1542667231
      redact:
        - password
        - private_key
        - secret
      subscriptions:
        - entity:webserver01
      system:
        arch: amd64
        libc_type: glibc
        vm_system: kvm
        vm_role: host
        cloud_provider: null
        network:
          interfaces:
            - addresses:
                - 127.0.0.1/8
                - ::1/128
              name: lo
            - addresses:
                - 172.28.128.3/24
                - fe80::a00:27ff:febc:be60/64
              mac: 08:00:27:bc:be:60
              name: enp0s8
        os: linux
        platform: centos
        platform_family: rhel
        platform_version: 7.4.1708
      sensu_agent_version: 1.0.0
      user: agent
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
        module.params["namespace"], "entities", module.params["name"],
    )

    try:
        entities = utils.prepare_result_list(utils.get(client, path))
    except errors.Error as e:
        module.fail_json(msg=str(e))

    module.exit_json(changed=False, objects=entities)


if __name__ == '__main__':
    main()

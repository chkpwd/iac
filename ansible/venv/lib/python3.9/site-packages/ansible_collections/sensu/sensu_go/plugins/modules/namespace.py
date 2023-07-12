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
module: namespace
author:
  - Paul Arthur (@flowerysong)
  - Aljaz Kosir (@aljazkosir)
  - Miha Plesko (@miha-plesko)
  - Tadej Borovsak (@tadeboro)
short_description: Manage Sensu namespaces
description:
  - Create, update or delete a Sensu namespace.
  - For more information, refer to the Sensu documentation at
    U(https://docs.sensu.io/sensu-go/latest/reference/rbac/#namespaces).
version_added: 1.0.0
extends_documentation_fragment:
  - sensu.sensu_go.requirements
  - sensu.sensu_go.auth
  - sensu.sensu_go.name
  - sensu.sensu_go.state
seealso:
  - module: sensu.sensu_go.namespace_info
'''

EXAMPLES = '''
- name: Create a new namespace
  sensu.sensu_go.namespace:
    name: production
    state: present

- name: Delete a namespace
  sensu.sensu_go.namespace:
    name: staging
    state: absent
'''

RETURN = '''
object:
  description: Object representing Sensu namespace.
  returned: success
  type: dict
  sample:
    name: default
'''

from ansible.module_utils.basic import AnsibleModule

from ..module_utils import arguments, errors, utils


def main():
    module = AnsibleModule(
        supports_check_mode=True,
        argument_spec=arguments.get_spec("auth", "name", "state"),
    )
    client = arguments.get_sensu_client(module.params['auth'])
    path = utils.build_core_v2_path(
        None, 'namespaces', module.params['name'],
    )
    payload = arguments.get_spec_payload(
        module.params, 'name'
    )
    try:
        changed, namespace = utils.sync(
            module.params['state'], client, path, payload, module.check_mode,
        )
        module.exit_json(changed=changed, object=namespace)
    except errors.Error as e:
        module.fail_json(msg=str(e))


if __name__ == '__main__':
    main()

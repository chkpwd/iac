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
module: role_info
author:
  - Paul Arthur (@flowerysong)
  - Manca Bizjak (@mancabizjak)
  - Aljaz Kosir (@aljazkosir)
  - Tadej Borovsak (@tadeboro)
short_description: List Sensu roles
description:
  - Retrieve information about Sensu roles.
  - For more information, refer to the Sensu documentation at
    U(https://docs.sensu.io/sensu-go/latest/reference/rbac/#roles-and-cluster-roles).
version_added: 1.0.0
extends_documentation_fragment:
  - sensu.sensu_go.requirements
  - sensu.sensu_go.auth
  - sensu.sensu_go.info
  - sensu.sensu_go.namespace
seealso:
  - module: sensu.sensu_go.role
'''

EXAMPLES = '''
- name: List all Sensu roles
  sensu.sensu_go.role_info:
  register: result

- name: Retrieve a specific Sensu role
  sensu.sensu_go.role_info:
    name: my-role
  register: result
'''

RETURN = '''
roles:
  description: List of Sensu roles.
  returned: success
  type: list
  elements: dict
  sample:
    - metadata:
        name: namespaced-resources-all-verbs
        namespace: default
      rules:
        - resource_names: []
          resources:
            - assets
            - checks
          verbs:
             - create
             - update
             - delete
'''

from ansible.module_utils.basic import AnsibleModule

from ..module_utils import arguments, errors, utils


def main():
    module = AnsibleModule(
        supports_check_mode=True,
        argument_spec=dict(
            arguments.get_spec("auth", "namespace"),
            name=dict()
        ),
    )

    client = arguments.get_sensu_client(module.params["auth"])
    path = utils.build_core_v2_path(
        module.params["namespace"], "roles", module.params["name"],
    )

    try:
        roles = utils.prepare_result_list(utils.get(client, path))
    except errors.Error as e:
        module.fail_json(msg=str(e))

    module.exit_json(changed=False, objects=roles)


if __name__ == '__main__':
    main()

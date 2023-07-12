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
module: role_binding_info
author:
  - Paul Arthur (@flowerysong)
  - Manca Bizjak (@mancabizjak)
  - Aljaz Kosir (@aljazkosir)
  - Tadej Borovsak (@tadeboro)
short_description: List Sensu role bindings
description:
  - Retrieve information about Sensu role bindings.
  - For more information, refer to the Sensu documentation at
    U(https://docs.sensu.io/sensu-go/latest/reference/rbac/#role-bindings-and-cluster-role-bindings).
version_added: 1.0.0
extends_documentation_fragment:
  - sensu.sensu_go.requirements
  - sensu.sensu_go.auth
  - sensu.sensu_go.info
  - sensu.sensu_go.namespace
seealso:
  - module: sensu.sensu_go.role_binding
'''

EXAMPLES = '''
- name: List all Sensu role bindings
  sensu.sensu_go.role_binding_info:
  register: result

- name: Retrieve a single Sensu role binding
  sensu.sensu_go.role_binding_info:
    name: my-role-binding
  register: result
'''

RETURN = '''
role_bindings:
  description: List of Sensu role bindings.
  returned: success
  type: list
  elements: dict
  sample:
    - metadata:
        name: event-reader-binding
        namespace: default
      role_ref:
        name: event-reader
        type: Role
      subjects:
        - name: bob
          type: User
'''

from ansible.module_utils.basic import AnsibleModule

from ..module_utils import arguments, errors, utils


def main():
    module = AnsibleModule(
        supports_check_mode=True,
        argument_spec=dict(
            arguments.get_spec("auth", "namespace"),
            name=dict()
        )
    )

    client = arguments.get_sensu_client(module.params["auth"])
    path = utils.build_core_v2_path(
        module.params["namespace"], "rolebindings", module.params["name"],
    )

    try:
        role_bindings = utils.prepare_result_list(utils.get(client, path))
    except errors.Error as e:
        module.fail_json(msg=str(e))

    module.exit_json(changed=False, objects=role_bindings)


if __name__ == '__main__':
    main()

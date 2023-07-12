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
module: cluster_role
author:
 - Paul Arthur (@flowerysong)
 - Manca Bizjak (@mancabizjak)
 - Aljaz Kosir (@aljazkosir)
 - Tadej Borovsak (@tadeboro)
short_description: Manage Sensu cluster roles
description:
  - Create, update or delete Sensu role.
  - For more information, refer to the Sensu documentation at
    U(https://docs.sensu.io/sensu-go/latest/reference/rbac/#roles-and-cluster-roles).
version_added: 1.0.0
extends_documentation_fragment:
  - sensu.sensu_go.requirements
  - sensu.sensu_go.auth
  - sensu.sensu_go.name
  - sensu.sensu_go.state
seealso:
  - module: sensu.sensu_go.cluster_role_info
  - module: sensu.sensu_go.cluster_role_binding
  - module: sensu.sensu_go.role
  - module: sensu.sensu_go.role_binding
options:
  rules:
    description:
      - Rules that the cluster role applies.
      - Must be non-empty if I(state) is C(present).
    type: list
    elements: dict
    suboptions:
      verbs:
        description:
          - Permissions to be applied by the rule.
        type: list
        elements: str
        required: yes
        choices: [get, list, create, update, delete]
      resources:
        description:
          - Types of resources the rule has permission to access.
        type: list
        elements: str
        required: yes
      resource_names:
        description:
          - Names of specific resources the rule has permission to access.
          - Note that for the C(create) verb, this argument will not be
            taken into account when enforcing RBAC, even if it is provided.
        type: list
        elements: str
'''

EXAMPLES = '''
- name: Create a cluster role
  sensu.sensu_go.cluster_role:
    name: readonly
    rules:
      - verbs:
          - get
          - list
        resources:
          - checks
          - entities

- name: Delete a cluster role
  sensu.sensu_go.cluster_role:
    name: readonly
    state: absent
'''

RETURN = '''
object:
  description: Object representing Sensu cluster role.
  returned: success
  type: dict
  sample:
    metadata:
      name: cluster-role
    rules:
      - resource_names:
          - sample-name
        resources:
          - assets
          - checks
        verbs:
          - get
          - list
'''

from ansible.module_utils.basic import AnsibleModule

from ..module_utils import arguments, errors, utils, role_utils


def main():
    module = AnsibleModule(
        supports_check_mode=True,
        argument_spec=dict(
            arguments.get_spec("auth", "name", "state"),
            rules=dict(
                type="list",
                elements="dict",
                options=dict(
                    verbs=dict(
                        required=True,
                        type="list",
                        elements="str",
                        choices=["get", "list", "create", "update", "delete"],
                    ),
                    resources=dict(
                        required=True,
                        type="list",
                        elements="str",
                    ),
                    resource_names=dict(
                        type="list",
                        elements="str",
                    ),
                )
            )
        )
    )

    msg = role_utils.validate_module_params(module.params)
    if msg:
        module.fail_json(msg=msg)

    client = arguments.get_sensu_client(module.params["auth"])
    path = utils.build_core_v2_path(
        None, "clusterroles", module.params["name"],
    )
    payload = arguments.get_mutation_payload(
        module.params, "rules"
    )

    try:
        changed, cluster_role = utils.sync(
            module.params['state'], client, path,
            payload, module.check_mode, role_utils.do_roles_differ
        )
        module.exit_json(changed=changed, object=cluster_role)
    except errors.Error as e:
        module.fail_json(msg=str(e))


if __name__ == '__main__':
    main()

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
module: cluster_role_info
author:
  - Paul Arthur (@flowerysong)
  - Manca Bizjak (@mancabizjak)
  - Aljaz Kosir (@aljazkosir)
  - Tadej Borovsak (@tadeboro)
short_description: List Sensu cluster roles
description:
  - Retrieve information about Sensu roles.
  - For more information, refer to the Sensu documentation at
    U(https://docs.sensu.io/sensu-go/latest/reference/rbac/#roles-and-cluster-roles).
version_added: 1.0.0
extends_documentation_fragment:
  - sensu.sensu_go.requirements
  - sensu.sensu_go.auth
  - sensu.sensu_go.info
seealso:
  - module: sensu.sensu_go.cluster_role
'''

EXAMPLES = '''
- name: List all Sensu cluster roles
  sensu.sensu_go.cluster_role_info:
  register: result

- name: Retrieve Sensu cluster role by name
  sensu.sensu_go.cluster_role_info:
    name: my-custer-role
  register: result
'''

RETURN = '''
roles:
  description: List of Sensu cluster roles.
  returned: success
  type: list
  elements: dict
  sample:
    - metadata:
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

from ..module_utils import arguments, errors, utils


def main():
    module = AnsibleModule(
        supports_check_mode=True,
        argument_spec=dict(
            arguments.get_spec("auth"),
            name=dict()
        ),
    )

    client = arguments.get_sensu_client(module.params["auth"])
    path = utils.build_core_v2_path(
        None, "clusterroles", module.params["name"],
    )

    try:
        cluster_roles = utils.prepare_result_list(utils.get(client, path))
    except errors.Error as e:
        module.fail_json(msg=str(e))

    module.exit_json(changed=False, objects=cluster_roles)


if __name__ == '__main__':
    main()

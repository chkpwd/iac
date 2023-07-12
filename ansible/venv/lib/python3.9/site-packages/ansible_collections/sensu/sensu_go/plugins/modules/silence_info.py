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
module: silence_info
author:
  - Paul Arthur (@flowerysong)
  - Aljaz Kosir (@aljazkosir)
  - Manca Bizjak (@mancabizjak)
  - Tadej Borovsak (@tadeboro)
short_description: List Sensu silence entries
description:
  - Retrieve information about Sensu silences.
  - For more information, refer to the Sensu documentation at
    U(https://docs.sensu.io/sensu-go/latest/reference/silencing/).
version_added: 1.0.0
extends_documentation_fragment:
  - sensu.sensu_go.requirements
  - sensu.sensu_go.auth
  - sensu.sensu_go.namespace
seealso:
  - module: sensu.sensu_go.silence
options:
  subscription:
    description:
      - The name of the subscription the entry should match. If left empty a silencing entry will
        contain an asterisk in the subscription position.
    type: str
  check:
    description:
     - The name of the check the entry should match. If left empty a silencing entry will contain an
       asterisk in the check position.
    type: str
'''

EXAMPLES = '''
- name: List all Sensu silence entries
  sensu.sensu_go.silence_info:
  register: result

- name: Fetch a specific silence with name proxy:awesome_check
  sensu.sensu_go.silence_info:
    subscription: proxy
    check: awesome_check
  register: result
'''

RETURN = '''
objects:
  description: List of Sensu silence entries.
  returned: success
  type: list
  elements: dict
  sample:
    - metadata:
        annotations: null
        labels: null
        name: entity:i-424242:*
        namespace: default
      begin: 1542671205
      check: null
      creator: admin
      expire: -1
      expire_on_resolve: false
      reason: null
      subscription: entity:i-424242
'''

from ansible.module_utils.basic import AnsibleModule

from ..module_utils import arguments, errors, utils


def main():
    module = AnsibleModule(
        supports_check_mode=True,
        argument_spec=dict(
            arguments.get_spec('auth', 'namespace'),
            subscription=dict(),
            check=dict(),
        ),
    )

    name = '{0}:{1}'.format(module.params['subscription'] or '*', module.params['check'] or '*')
    client = arguments.get_sensu_client(module.params["auth"])
    path = utils.build_core_v2_path(
        module.params["namespace"], "silenced", None if name == "*:*" else name,
    )

    try:
        silences = utils.prepare_result_list(utils.get(client, path))
    except errors.Error as e:
        module.fail_json(msg=str(e))

    module.exit_json(changed=False, objects=silences)


if __name__ == '__main__':
    main()

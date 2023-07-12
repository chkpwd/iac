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
module: tessen
author:
 - Paul Arthur (@flowerysong)
 - Manca Bizjak (@mancabizjak)
 - Aljaz Kosir (@aljazkosir)
 - Tadej Borovsak (@tadeboro)
short_description: Manage Sensu's Tessen configuration
description:
  - Enable or disable Tessen service.
  - For more information, refer to the Sensu documentation at
    U(https://docs.sensu.io/sensu-go/latest/reference/tessen/).
version_added: 1.0.0
extends_documentation_fragment:
  - sensu.sensu_go.requirements
  - sensu.sensu_go.auth
options:
  state:
    description:
      - Enable or disable sending anonymized data to Sensu Inc.
    choices: [ enabled, disabled ]
    type: str
    required: True
'''

EXAMPLES = '''
- name: Disable Tessen
  sensu.sensu_go.tessen:
    state: disabled
  register: result
'''

RETURN = '''
object:
  description: Object representing Sensu tessen.
  returned: success
  type: dict
  sample:
    opt_out: false
'''

from ansible.module_utils.basic import AnsibleModule

from ..module_utils import arguments, errors, utils


def get(client, path):
    resp = client.get(path)
    if resp.status != 200:
        raise errors.SyncError(
            "GET {0} failed with status {1}: {2}".format(path, resp.status, resp.data))
    return resp.json


def sync(client, path, payload, check_mode):
    remote_object = get(client, path)

    if utils.do_differ(remote_object, payload):
        if check_mode:
            return True, payload
        utils.put(client, path, payload)
        return True, get(client, path)

    return False, remote_object


def main():
    module = AnsibleModule(
        supports_check_mode=True,
        argument_spec=dict(
            arguments.get_spec('auth'),
            state=dict(
                choices=['enabled', 'disabled'],
                required=True,
            )
        )
    )
    client = arguments.get_sensu_client(module.params['auth'])
    path = utils.build_core_v2_path(None, 'tessen')
    payload = dict(
        opt_out=module.params['state'] == 'disabled'
    )

    try:
        changed, tessen = sync(client, path, payload, module.check_mode)
        module.exit_json(changed=changed, object=tessen)
    except errors.Error as e:
        module.fail_json(msg=str(e))


if __name__ == '__main__':
    main()

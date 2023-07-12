#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2017 Cisco and/or its affiliates.
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = '''
---
module: nso_config
extends_documentation_fragment:
- cisco.nso.nso

short_description: Manage Cisco NSO configuration and service synchronization.
description:
  - This module provides support for managing configuration in Cisco NSO and
    can also ensure services are in sync.
requirements:
  - Cisco NSO version 3.4.12 or higher, 4.2.7 or higher,
    4.3.8 or higher, 4.4.3 or higher, 4.5 or higher.
author: "Claes Nästén (@cnasten)"
options:
  data:
    description: >
      NSO data in format as | display json converted to YAML. List entries can
      be annotated with a __state entry. Set to in-sync/deep-in-sync for
      services to verify service is in sync with the network. Set to absent in
      list entries to ensure they are deleted if they exist in NSO.
    required: true
    type: dict
  commit_flags:
     description: >
       A list containing commit flags. See the API documentation for
       supported commit flags.
       https://developer.cisco.com/docs/nso/guides/#!life-cycle-operations-how-to-manipulate-existing-services-and-devices/commit-flags-and-device-service-actions
     type: list
     elements: str
'''

EXAMPLES = '''
- name: CREATE DEVICE IN NSO
  cisco.nso.nso_config:
    url: https://10.10.20.49/jsonrpc
    username: developer
    password: C1sco12345
    data:
      tailf-ncs:devices:
        device:
        - address: 10.10.20.175
          description: CONFIGURED BY ANSIBLE!
          name: dist-rtr01
          authgroup: "labadmin"
          device-type:
            cli:
              ned-id: "cisco-ios-cli-6.44"
            port: "22"
            state:
              admin-state: "unlocked"

- name: ADD NEW LOOPBACK
  cisco.nso.nso_config:
    url: https://10.10.20.49/jsonrpc
    username: developer
    password: C1sco12345
    data:
        tailf-ncs:devices:
        device:
        - name: dist-rtr01
          config:
            tailf-ned-cisco-ios:interface:
                Loopback:
                - name: "1"
                  description: Created by Ansible!

- name: CONFIGURE IP ADDRESS ON LOOPBACK
  cisco.nso.nso_config:
    url: https://10.10.20.49/jsonrpc
    username: developer
    password: C1sco12345
    data:
      tailf-ncs:devices:
        device:
        - name: dist-rtr01
          config:
            tailf-ned-cisco-ios:interface:
              Loopback:
              - name: "1"
                description: Created by Ansible!
                ip:
                  address:
                    primary:
                      address: 10.10.10.10
                      mask: 255.255.255.255

- name: CONFIGURE NTP SERVER ON DEVICE
  cisco.nso.nso_config:
    url: https://10.10.20.49/jsonrpc
    username: developer
    password: C1sco12345
    data:
      tailf-ncs:devices:
        device:
        - name: dist-rtr01
          config:
            tailf-ned-cisco-ios:ntp:
              server:
                peer-list:
                  - name: 2.2.2.2
'''

RETURN = '''
changes:
    description: List of changes
    returned: always
    type: complex
    sample:
        - path: "/ncs:devices/device{dist-rtr01}/config/ios:interface/Loopback{1}/ip/address/primary/address"
          from: null
          to: "10.10.10.10"
          type: set
    contains:
        path:
            description: Path to value changed
            returned: always
            type: str
        from:
            description: Previous value if any, else null
            returned: When previous value is present on value change
            type: str
diffs:
    description: List of sync changes
    returned: always
    type: complex
    contains:
        path:
            description: keypath to service changed
            returned: always
            type: str
        diff:
            description: configuration difference triggered the re-deploy
            returned: always
            type: str
commit_result:
    description: Return values from commit operation
    returned: always
    type: complex
    contains:
      commit_queue:
        description: Commit queue ID and status, if any
        returned: When commit-queue is set in commit_flags
        type: dict
    sample:
      - {
                "commit_queue": {
                    "id": 1611776004976,
                    "status": "async"
                }
            }

'''

from ansible_collections.cisco.nso.plugins.module_utils.nso import connect, verify_version, nso_argument_spec
from ansible_collections.cisco.nso.plugins.module_utils.nso import State, ValueBuilder
from ansible_collections.cisco.nso.plugins.module_utils.nso import ModuleFailException, NsoException
from ansible.module_utils.basic import AnsibleModule


class NsoConfig(object):
    REQUIRED_VERSIONS = [
        (4, 5),
        (4, 4, 3),
        (4, 3, 8),
        (4, 2, 7),
        (3, 4, 12)
    ]

    def __init__(self, check_mode, client, data, commit_flags):
        self._check_mode = check_mode
        self._client = client
        self._data = data
        self._commit_flags = commit_flags

        self._changes = []
        self._diffs = []
        self._commit_result = []

    def main(self):
        # build list of values from configured data
        value_builder = ValueBuilder(self._client)
        for key, value in self._data.items():
            value_builder.build('', key, value)

        self._data_write(value_builder.values)

        # check sync AFTER configuration is written
        sync_values = self._sync_check(value_builder.values)
        self._sync_ensure(sync_values)

        return self._changes, self._diffs, self._commit_result

    def _data_write(self, values):
        th = self._client.get_trans(mode='read_write')

        for value in values:
            if value.state == State.SET:
                self._client.set_value(th, value.path, value.value)
            elif value.state == State.PRESENT:
                self._client.create(th, value.path)
            elif value.state == State.ABSENT:
                self._client.delete(th, value.path)

        changes = self._client.get_trans_changes(th)
        for change in changes:
            if change['op'] == 'value_set':
                self._changes.append({
                    'path': change['path'],
                    'from': change['old'] or None,
                    'to': change['value'],
                    'type': 'set'
                })
            elif change['op'] in ('created', 'deleted'):
                self._changes.append({
                    'path': change['path'],
                    'type': change['op'][:-1]
                })

        if len(changes) > 0:
            # Fix for validate_commit method not working with commit flags prior to 5.4.
            # If version < 5.4 then don't send the flags to validate_commit
            version = float(self._client._version[0:self._client._version.find('.') + 2:])
            if version >= 5.4:
                warnings = self._client.validate_commit(th, self._commit_flags)
            else:
                warnings = self._client.validate_commit(th)
            if len(warnings) > 0:
                raise NsoException(
                    'failed to validate transaction with warnings: {0}'.format(
                        ', '.join((str(warning) for warning in warnings))), {})
        if self._check_mode or len(changes) == 0:
            self._client.delete_trans(th)
        else:
            if self._commit_flags:
                result = self._client.commit(th, self._commit_flags)
                self._commit_result.append(result)
            else:
                result = self._client.commit(th)
                self._commit_result.append(result)

    def _sync_check(self, values):
        sync_values = []

        for value in values:
            if value.state in (State.CHECK_SYNC, State.IN_SYNC):
                action = 'check-sync'
            elif value.state in (State.DEEP_CHECK_SYNC, State.DEEP_IN_SYNC):
                action = 'deep-check-sync'
            else:
                action = None

            if action is not None:
                action_path = '{0}/{1}'.format(value.path, action)
                action_params = {'outformat': 'cli'}
                resp = self._client.run_action(None, action_path, action_params)
                if len(resp) > 0:
                    sync_values.append(
                        ValueBuilder.Value(value.path, value.state, resp[0]['value']))

        return sync_values

    def _sync_ensure(self, sync_values):
        for value in sync_values:
            if value.state in (State.CHECK_SYNC, State.DEEP_CHECK_SYNC):
                raise NsoException(
                    '{0} out of sync, diff {1}'.format(value.path, value.value), {})

            action_path = '{0}/{1}'.format(value.path, 're-deploy')
            if not self._check_mode:
                result = self._client.run_action(None, action_path)
                if not result:
                    raise NsoException(
                        'failed to re-deploy {0}'.format(value.path), {})

            self._changes.append({'path': value.path, 'type': 're-deploy'})
            self._diffs.append({'path': value.path, 'diff': value.value})


def main():
    argument_spec = dict(
        data=dict(required=True, type='dict'),
        commit_flags=dict(required=False, type='list', elements='str')
    )

    argument_spec.update(nso_argument_spec)

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )
    p = module.params
    client = connect(p)
    nso_config = NsoConfig(module.check_mode, client, p['data'], p['commit_flags'])
    try:
        verify_version(client, NsoConfig.REQUIRED_VERSIONS)

        changes, diffs, commit_result = nso_config.main()
        client.logout()

        changed = len(changes) > 0
        module.exit_json(
            changed=changed, changes=changes, diffs=diffs, commit_result=commit_result)

    except NsoException as ex:
        client.logout()
        module.fail_json(msg=ex.message)
    except ModuleFailException as ex:
        client.logout()
        module.fail_json(msg=ex.message)


if __name__ == '__main__':
    main()

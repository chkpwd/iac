#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2018, Yanis Guenane <yanis+ansible@guenane.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


DOCUMENTATION = '''
---
module: vultr_block_storage
short_description: Manages block storage volumes on Vultr.
description:
  - Manage block storage volumes on Vultr.
author: "Yanis Guenane (@Spredzy)"
version_added: "0.1.0"
options:
  name:
    description:
      - Name of the block storage volume.
    required: true
    aliases: [ description, label ]
    type: str
  size:
    description:
      - Size of the block storage volume in GB.
      - Required if I(state) is present.
      - If it's larger than the volume's current size, the volume will be resized.
    type: int
  region:
    description:
      - Region the block storage volume is deployed into.
      - Required if I(state) is present.
    type: str
  state:
    description:
      - State of the block storage volume.
    default: present
    choices: [ present, absent, attached, detached ]
    type: str
  attached_to_SUBID:
    description:
      - The ID of the server the volume is attached to.
      - Required if I(state) is attached.
    aliases: [ attached_to_id ]
    type: int
  live_attachment:
    description:
      - Whether the volume should be attached/detached, even if the server not stopped.
    type: bool
    default: True
extends_documentation_fragment:
- ngine_io.vultr.vultr

'''

EXAMPLES = '''
- name: Ensure a block storage volume is present
  ngine_io.vultr.vultr_block_storage:
    name: myvolume
    size: 10
    region: Amsterdam

- name: Ensure a block storage volume is absent
  ngine_io.vultr.vultr_block_storage:
    name: myvolume
    state: absent

- name: Ensure a block storage volume exists and is attached to server 114
  ngine_io.vultr.vultr_block_storage:
    name: myvolume
    state: attached
    attached_to_id: 114
    size: 10

- name: Ensure a block storage volume exists and is not attached to any server
  ngine_io.vultr.vultr_block_storage:
    name: myvolume
    state: detached
    size: 10
'''

RETURN = '''
---
vultr_api:
  description: Response from Vultr API with a few additions/modification
  returned: success
  type: complex
  contains:
    api_account:
      description: Account used in the ini file to select the key
      returned: success
      type: str
      sample: default
    api_timeout:
      description: Timeout used for the API requests
      returned: success
      type: int
      sample: 60
    api_retries:
      description: Amount of max retries for the API requests
      returned: success
      type: int
      sample: 5
    api_retry_max_delay:
      description: Exponential backoff delay in seconds between retries up to this max delay value.
      returned: success
      type: int
      sample: 12
    api_endpoint:
      description: Endpoint used for the API requests
      returned: success
      type: str
      sample: "https://api.vultr.com"
vultr_block_storage:
  description: Response from Vultr API
  returned: success
  type: complex
  contains:
    attached_to_id:
      description: The ID of the server the volume is attached to
      returned: success
      type: str
      sample: "10194376"
    cost_per_month:
      description: Cost per month for the volume
      returned: success
      type: float
      sample: 1.00
    date_created:
      description: Date when the volume was created
      returned: success
      type: str
      sample: "2017-08-26 12:47:48"
    id:
      description: ID of the block storage volume
      returned: success
      type: str
      sample: "1234abcd"
    name:
      description: Name of the volume
      returned: success
      type: str
      sample: "ansible-test-volume"
    region:
      description: Region the volume was deployed into
      returned: success
      type: str
      sample: "New Jersey"
    size:
      description: Information about the volume size in GB
      returned: success
      type: int
      sample: 10
    status:
      description: Status about the deployment of the volume
      returned: success
      type: str
      sample: "active"

'''
from ansible.module_utils.basic import AnsibleModule
from ..module_utils.vultr import (
    Vultr,
    vultr_argument_spec,
)


class AnsibleVultrBlockStorage(Vultr):

    def __init__(self, module):
        super(AnsibleVultrBlockStorage, self).__init__(module, "vultr_block_storage")

        self.returns = {
            'SUBID': dict(key='id'),
            'label': dict(key='name'),
            'DCID': dict(key='region', transform=self._get_region_name),
            'attached_to_SUBID': dict(key='attached_to_id'),
            'cost_per_month': dict(convert_to='float'),
            'date_created': dict(),
            'size_gb': dict(key='size', convert_to='int'),
            'status': dict()
        }

    def _get_region_name(self, region):
        return self.get_region(region, 'DCID').get('name')

    def get_block_storage_volumes(self):
        volumes = self.api_query(path="/v1/block/list")
        if volumes:
            for volume in volumes:
                if volume.get('label') == self.module.params.get('name'):
                    return volume
        return {}

    def present_block_storage_volume(self):
        volume = self.get_block_storage_volumes()
        if not volume:
            volume = self._create_block_storage_volume(volume)
        return volume

    def _create_block_storage_volume(self, volume):
        self.result['changed'] = True
        data = {
            'label': self.module.params.get('name'),
            'DCID': self.get_region().get('DCID'),
            'size_gb': self.module.params.get('size')
        }
        self.result['diff']['before'] = {}
        self.result['diff']['after'] = data

        if not self.module.check_mode:
            self.api_query(
                path="/v1/block/create",
                method="POST",
                data=data
            )
            volume = self.get_block_storage_volumes()
        return volume

    def absent_block_storage_volume(self):
        volume = self.get_block_storage_volumes()
        if volume:
            self.result['changed'] = True

            data = {
                'SUBID': volume['SUBID'],
            }

            self.result['diff']['before'] = volume
            self.result['diff']['after'] = {}

            if not self.module.check_mode:
                self.api_query(
                    path="/v1/block/delete",
                    method="POST",
                    data=data
                )
        return volume

    def detached_block_storage_volume(self):
        volume = self.present_block_storage_volume()
        if volume.get('attached_to_SUBID') is None:
            return volume

        self.result['changed'] = True

        if not self.module.check_mode:
            data = {
                'SUBID': volume['SUBID'],
                'live': self.get_yes_or_no('live_attachment')
            }
            self.api_query(
                path='/v1/block/detach',
                method='POST',
                data=data
            )

            volume = self.get_block_storage_volumes()
        else:
            volume['attached_to_SUBID'] = None

        self.result['diff']['after'] = volume

        return volume

    def attached_block_storage_volume(self):
        expected_server = self.module.params.get('attached_to_SUBID')
        volume = self.present_block_storage_volume()
        server = volume.get('attached_to_SUBID')
        if server == expected_server:
            return volume

        if server is not None:
            self.module.fail_json(
                msg='Volume already attached to server %s' % server
            )

        self.result['changed'] = True

        if not self.module.check_mode:
            data = {
                'SUBID': volume['SUBID'],
                # This API call expects a param called attach_to_SUBID,
                # but all the BlockStorage API response payloads call
                # this parameter attached_to_SUBID. So we'll standardize
                # to the latter and attached_to_id, but we'll pass the
                # expected attach_to_SUBID to this API call.
                'attach_to_SUBID': expected_server,
                'live': self.get_yes_or_no('live_attachment'),
            }
            self.api_query(
                path='/v1/block/attach',
                method='POST',
                data=data
            )
            volume = self.get_block_storage_volumes()
        else:
            volume['attached_to_SUBID'] = expected_server

        self.result['diff']['after'] = volume

        return volume

    def ensure_volume_size(self, volume, expected_size):
        curr_size = volume.get('size_gb')
        # When creating, attaching, or detaching a volume in check_mode,
        # sadly, size_gb doesn't exist, because those methods return the
        # result of get_block_storage_volumes, which is {} on check_mode.
        if curr_size is None or curr_size >= expected_size:
            # we only resize volumes that are smaller than
            # expected. There's no shrinking operation.
            return volume

        self.result['changed'] = True

        volume['size_gb'] = expected_size
        self.result['diff']['after'] = volume

        if not self.module.check_mode:
            data = {'SUBID': volume['SUBID'], 'size_gb': expected_size}
            self.api_query(
                path='/v1/block/resize',
                method='POST',
                data=data,
            )

        return volume


def main():
    argument_spec = vultr_argument_spec()
    argument_spec.update(dict(
        name=dict(type='str', required=True, aliases=['description', 'label']),
        size=dict(type='int'),
        region=dict(type='str'),
        state=dict(
            type='str',
            choices=['present', 'absent', 'attached', 'detached'],
            default='present'
        ),
        attached_to_SUBID=dict(type='int', aliases=['attached_to_id']),
        live_attachment=dict(type='bool', default=True)
    ))

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'present', ['size', 'region']],
            ['state', 'detached', ['size', 'region']],
            ['state', 'attached', ['size', 'region', 'attached_to_SUBID']],
        ]
    )

    vultr_block_storage = AnsibleVultrBlockStorage(module)

    desired_state = module.params.get('state')
    if desired_state == "absent":
        volume = vultr_block_storage.absent_block_storage_volume()
    elif desired_state == 'attached':
        volume = vultr_block_storage.attached_block_storage_volume()
    elif desired_state == 'detached':
        volume = vultr_block_storage.detached_block_storage_volume()
    else:
        volume = vultr_block_storage.present_block_storage_volume()

    expected_size = module.params.get('size')
    if expected_size and desired_state != 'absent':
        volume = vultr_block_storage.ensure_volume_size(
            volume,
            expected_size
        )

    result = vultr_block_storage.get_result(volume)
    module.exit_json(**result)


if __name__ == '__main__':
    main()

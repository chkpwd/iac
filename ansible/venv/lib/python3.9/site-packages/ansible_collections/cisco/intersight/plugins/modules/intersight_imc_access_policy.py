#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: intersight_imc_access_policy
short_description: IMC Access Policy configuration for Cisco Intersight
description:
  - IMC Access Policy configuration for Cisco Intersight.
  - Used to configure IP addresses and VLAN used for external connectivity to Cisco IMC.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs).
extends_documentation_fragment: intersight
options:
  state:
    description:
      - If C(present), will verify the resource is present and will create if needed.
      - If C(absent), will verify the resource is absent and will delete if needed.
    choices: [present, absent]
    default: present
  organization:
    description:
      - The name of the Organization this resource is assigned to.
      - Profiles and Policies that are created within a Custom Organization are applicable only to devices in the same Organization.
    default: default
  name:
    description:
      - The name assigned to the IMC Access Policy.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    required: true
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
  descrption:
    description:
      - The user-defined description of the IMC access policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    aliases: [descr]
  vlan_id:
    description:
      - VLAN to be used for server access over Inband network.
    required: true
    type: int
  ip_pool:
    description:
      - IP Pool used to assign IP address and other required network settings.
    required: true
author:
  - David Soper (@dsoper2)
version_added: '2.10'
'''

EXAMPLES = r'''
- name: Configure IMC Access policy
  intersight_imc_access_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: sjc02-d23-access
    description: IMC access for SJC02 rack D23
    tags:
      - Site: D23
    vlan_id: 131
    ip_pool: sjc02-d23-ext-mgmt

- name: Delete IMC Access policy
  intersight_imc_access_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: sjc02-d23-access
    state: absent
'''

RETURN = r'''
api_repsonse:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "sjc02-d23-access",
        "ObjectType": "access.Policy",
        "Profiles": [
            {
                "Moid": "5e4ec7ae77696e2d30840cfc",
                "ObjectType": "server.Profile",
            },
            {
                "Moid": "5e84d78777696e2d302ec195",
                "ObjectType": "server.Profile",
            }
        ],
        "Tags": [
            {
                "Key": "Site",
                "Value": "SJC02"
            }
        ]
    }
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec, compare_values


def main():
    argument_spec = intersight_argument_spec
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr'], default=''),
        tags=dict(type='list', default=[]),
        vlan_id=dict(type='int', required=True),
        ip_pool=dict(type='str', required=True),
    )

    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''
    intersight.api_body = {
        'Name': intersight.module.params['name'],
        'Tags': intersight.module.params['tags'],
        'Description': intersight.module.params['description'],
        'InbandVlan': intersight.module.params['vlan_id'],
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
    }

    # get the current state of the resource
    intersight.get_resource(
        resource_path='/access/Policies',
        query_params={
            '$filter': "Name eq '" + intersight.module.params['name'] + "'",
            '$expand': 'Organization',
        },
    )

    moid = None
    resource_values_match = False
    if intersight.result['api_response'].get('Moid'):
        # resource exists and moid was returned
        moid = intersight.result['api_response']['Moid']
        if module.params['state'] == 'present':
            resource_values_match = compare_values(intersight.api_body, intersight.result['api_response'])
        else:  # state == 'absent'
            intersight.delete_resource(
                moid=moid,
                resource_path='/access/Policies',
            )
            moid = None

    if module.params['state'] == 'present' and not resource_values_match:
        # remove read-only Organization key
        intersight.api_body.pop('Organization')
        if not moid:
            # GET Organization Moid
            intersight.get_resource(
                resource_path='/organization/Organizations',
                query_params={
                    '$filter': "Name eq '" + intersight.module.params['organization'] + "'",
                    '$select': 'Moid',
                },
            )
            organization_moid = None
            if intersight.result['api_response'].get('Moid'):
                # resource exists and moid was returned
                organization_moid = intersight.result['api_response']['Moid']
            # Organization must be set, but can't be changed after initial POST
            intersight.api_body['Organization'] = {
                'Moid': organization_moid,
            }
        intersight.configure_resource(
            moid=moid,
            resource_path='/access/Policies',
            body=intersight.api_body,
            query_params={
                '$filter': "Name eq '" + intersight.module.params['name'] + "'",
            },
        )

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()

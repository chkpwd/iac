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
module: intersight_ntp_policy
short_description: NTP policy configuration for Cisco Intersight
description:
  - NTP policy configuration for Cisco Intersight.
  - Used to configure NTP servers and timezone settings on Cisco Intersight managed devices.
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
      - The name assigned to the NTP policy.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    required: true
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
  description:
    description:
      - The user-defined description of the NTP policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    aliases: [descr]
  enable:
    description:
      - Enable or disable NTP.
    type: bool
    default: true
  ntp_servers:
    description:
      - List of NTP servers configured on the endpoint.
    type: list
  timezone:
    description:
      - Timezone of services on the endpoint.
author:
  - David Soper (@dsoper2)
version_added: '2.10'
'''

EXAMPLES = r'''
- name: Configure NTP Policy
  cisco.intersight.intersight_ntp_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: DevNet
    name: lab-ntp
    description: NTP policy for lab use
    tags:
      - Key: Site
        Value: RCDN
    ntp_servers:
      - ntp.esl.cisco.com
    timezone: America/Chicago

- name: Delete NTP Policy
  cisco.intersight.intersight_ntp_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: DevNet
    name: lab-ntp
    state: absent
'''

RETURN = r'''
api_repsonse:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "lab-ntp",
        "ObjectType": "ntp.Policy",
        "Tags": [
            {
                "Key": "Site",
                "Value": "RCDN"
            }
        ]
    }
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec


def main():
    argument_spec = intersight_argument_spec
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr'], default=''),
        tags=dict(type='list', default=[]),
        enable=dict(type='bool', default=True),
        ntp_servers=dict(type='list', default=[]),
        timezone=dict(type='str', default=''),
    )

    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''
    #
    # Argument spec above, resource path, and API body should be the only code changed in each policy module
    #
    # Resource path used to configure policy
    resource_path = '/ntp/Policies'
    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name'],
        'Tags': intersight.module.params['tags'],
        'Description': intersight.module.params['description'],
        'Enabled': intersight.module.params['enable'],
        'NtpServers': intersight.module.params['ntp_servers'],
        'Timezone': intersight.module.params['timezone'],
    }

    #
    # Code below should be common across all policy modules
    #
    intersight.configure_policy_or_profile(resource_path=resource_path)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()

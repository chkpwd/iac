#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Ansible module to manage Check Point Firewall (c) 2019
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

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = """
---
module: cp_mgmt_vpn_community_star
short_description: Manages vpn-community-star objects on Check Point over Web Services API
description:
  - Manages vpn-community-star objects on Check Point devices including creating, updating and removing objects.
  - All operations are performed over Web Services API.
version_added: "1.0.0"
author: "Or Soffer (@chkp-orso)"
options:
  name:
    description:
      - Object name.
    type: str
    required: True
  center_gateways:
    description:
      - Collection of center VPN Gateway and VPN Device objects identified by the name or UID.
    type: list
    elements: str
  encryption_method:
    description:
      - The encryption method to be used.
    type: str
    choices: ['prefer ikev2 but support ikev1', 'ikev2 only', 'ikev1 for ipv4 and ikev2 for ipv6 only']
  encryption_suite:
    description:
      - The encryption suite to be used.
    type: str
    choices: ['suite-b-gcm-256', 'custom', 'vpn b', 'vpn a', 'suite-b-gcm-128']
  granular_encryptions:
    description:
      - VPN granular encryption settings.
    type: list
    elements: dict
    version_added: "5.1.0"
    suboptions:
      internal_gateway:
        description:
          - Internally managed Check Point gateway identified by name or UID, or 'Any' for all internal-gateways participants in this community.
        type: str
      external_gateway:
        description:
          - Externally managed or 3rd party gateway identified by name or UID.
        type: str
      encryption_method:
        description:
          - The encryption method to be used.
        type: str
        choices: ['prefer ikev2 but support ikev1', 'ikev2 only', 'ikev1 for ipv4 and ikev2 for ipv6 only']
      encryption_suite:
        description:
          - The encryption suite to be used.
        type: str
        choices: ['suite-b-gcm-256', 'custom', 'vpn b', 'vpn a', 'suite-b-gcm-128']
      ike_phase_1:
        description:
          - Ike Phase 1 settings. Only applicable when the encryption-suite is set to [custom].
        type: dict
        suboptions:
          encryption_algorithm:
            description:
              - The encryption algorithm to be used.
            type: str
            choices: ['cast', 'aes-256', 'des', 'aes-128', '3des']
          data_integrity:
            description:
              - The hash algorithm to be used.
            type: str
            choices: ['aes-xcbc', 'sha1', 'sha256', 'sha384', 'sha512', 'md5']
          diffie_hellman_group:
            description:
              - The Diffie-Hellman group to be used.
            type: str
            choices: ['group-1', 'group-2', 'group-5', 'group-14', 'group-15', 'group-16', 'group-17', 'group-18', 'group-19', 'group-20', 'group-24']
          ike_p1_rekey_time:
            description:
              - Indicates the time interval for IKE phase 1 renegotiation.
            type: int
          ike_p1_rekey_time_unit:
            description:
              - Indicates the time unit for [ike-p1-rekey-time-unit] parameter, rounded up to minutes scale.
            type: str
            choices: ['days', 'hours', 'minutes', 'seconds']
      ike_phase_2:
        description:
          - Ike Phase 2 settings. Only applicable when the encryption-suite is set to [custom].
        type: dict
        suboptions:
          encryption_algorithm:
            description:
              - The encryption algorithm to be used.
            type: str
            choices: ['cast', 'aes-gcm-256', 'cast-40', 'aes-256', 'des', 'aes-128', '3des', 'des-40cp', 'aes-gcm-128', 'none']
          data_integrity:
            description:
              - The hash algorithm to be used.
            type: str
            choices: ['aes-xcbc', 'sha1', 'sha256', 'sha384', 'sha512', 'md5']
          ike_p2_use_pfs:
            description:
              - Indicates whether Perfect Forward Secrecy (PFS) is being used for IKE phase 2.
            type: bool
          ike_p2_pfs_dh_grp:
            description:
              - The Diffie-Hellman group to be used.
            type: str
            choices: ['group-1', 'group-2', 'group-5', 'group-14', 'group-15', 'group-16', 'group-17', 'group-18', 'group-19', 'group-20', 'group-24']
          ike_p2_rekey_time:
            description:
              - Indicates the time interval for IKE phase 2 renegotiation.
            type: int
          ike_p2_rekey_time_unit:
            description:
              - Indicates the time unit for [ike-p2-rekey-time-unit] parameter.
            type: str
            choices: ['days', 'hours', 'minutes', 'seconds']
  ike_phase_1:
    description:
      - Ike Phase 1 settings. Only applicable when the encryption-suite is set to [custom].
    type: dict
    suboptions:
      data_integrity:
        description:
          - The hash algorithm to be used.
        type: str
        choices: ['aes-xcbc', 'sha1', 'sha256', 'sha384', 'md5']
      diffie_hellman_group:
        description:
          - The Diffie-Hellman group to be used.
        type: str
        choices: ['group-1', 'group-2', 'group-5', 'group-14', 'group-19', 'group-20']
      encryption_algorithm:
        description:
          - The encryption algorithm to be used.
        type: str
        choices: ['cast', 'aes-256', 'des', 'aes-128', '3des']
      ike_p1_rekey_time:
        description:
          - Indicates the time interval for IKE phase 1 renegotiation.
        type: int
        version_added: "5.1.0"
      ike_p1_rekey_time_unit:
        description:
          - Indicates the time unit for [ike-p1-rekey-time-unit] parameter, rounded up to minutes scale.
        type: str
        choices: ['days', 'hours', 'minutes', 'seconds']
        version_added: "5.1.0"
  ike_phase_2:
    description:
      - Ike Phase 2 settings. Only applicable when the encryption-suite is set to [custom].
    type: dict
    suboptions:
      data_integrity:
        description:
          - The hash algorithm to be used.
        type: str
        choices: ['aes-xcbc', 'sha1', 'sha256', 'sha384', 'md5']
      encryption_algorithm:
        description:
          - The encryption algorithm to be used.
        type: str
        choices: ['cast', 'aes-gcm-256', 'cast-40', 'aes-256', 'des', 'aes-128', '3des', 'des-40cp', 'aes-gcm-128', 'none']
      ike_p2_use_pfs:
        description:
          - Indicates whether Perfect Forward Secrecy (PFS) is being used for IKE phase 2.
        type: bool
        version_added: "5.1.0"
      ike_p2_pfs_dh_grp:
        description:
          - The Diffie-Hellman group to be used.
        type: str
        choices: ['group-1', 'group-2', 'group-5', 'group-14', 'group-15', 'group-16', 'group-17', 'group-18', 'group-19', 'group-20', 'group-24']
        version_added: "5.1.0"
      ike_p2_rekey_time:
        description:
          - Indicates the time interval for IKE phase 2 renegotiation.
        type: int
        version_added: "5.1.0"
      ike_p2_rekey_time_unit:
        description:
          - Indicates the time unit for [ike-p2-rekey-time-unit] parameter.
        type: str
        choices: ['days', 'hours', 'minutes', 'seconds']
        version_added: "5.1.0"
  mesh_center_gateways:
    description:
      - Indicates whether the meshed community is in center.
    type: bool
  override_vpn_domains:
    description:
      - The Overrides VPN Domains of the participants GWs.
    type: list
    elements: dict
    version_added: "5.1.0"
    suboptions:
      gateway:
        description:
          - Participant gateway in override VPN domain identified by the name or UID.
        type: str
      vpn_domain:
        description:
          - VPN domain network identified by the name or UID.
        type: str
  satellite_gateways:
    description:
      - Collection of Gateway objects representing satellite gateways identified by the name or UID.
    type: list
    elements: str
  shared_secrets:
    description:
      - Shared secrets for external gateways.
    type: list
    elements: dict
    suboptions:
      external_gateway:
        description:
          - External gateway identified by the name or UID.
        type: str
      shared_secret:
        description:
          - Shared secret.
        type: str
  tags:
    description:
      - Collection of tag identifiers.
    type: list
    elements: str
  tunnel_granularity:
    description:
      - VPN tunnel sharing option to be used.
    type: str
    choices: ['per_host', 'per_subnet', 'universal']
    version_added: "5.1.0"
  use_shared_secret:
    description:
      - Indicates whether the shared secret should be used for all external gateways.
    type: bool
  color:
    description:
      - Color of the object. Should be one of existing colors.
    type: str
    choices: ['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green', 'khaki', 'orchid', 'dark orange', 'dark sea green',
             'pink', 'turquoise', 'dark blue', 'firebrick', 'brown', 'forest green', 'gold', 'dark gold', 'gray', 'dark gray', 'light green', 'lemon chiffon',
             'coral', 'sea green', 'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive', 'orange', 'red', 'sienna', 'yellow']
  comments:
    description:
      - Comments string.
    type: str
  details_level:
    description:
      - The level of detail for some of the fields in the response can vary from showing only the UID value of the object to a fully detailed
        representation of the object.
    type: str
    choices: ['uid', 'standard', 'full']
  ignore_warnings:
    description:
      - Apply changes ignoring warnings.
    type: bool
  ignore_errors:
    description:
      - Apply changes ignoring errors. You won't be able to publish such a changes. If ignore-warnings flag was omitted - warnings will also be ignored.
    type: bool
extends_documentation_fragment: check_point.mgmt.checkpoint_objects
"""

EXAMPLES = """
- name: add-vpn-community-star
  cp_mgmt_vpn_community_star:
    center_gateways: Second_Security_Gateway
    encryption_method: prefer ikev2 but support ikev1
    encryption_suite: custom
    ike_phase_1:
      data_integrity: sha1
      diffie_hellman_group: group 19
      encryption_algorithm: aes-128
    ike_phase_2:
      data_integrity: aes-xcbc
      encryption_algorithm: aes-gcm-128
    name: New_VPN_Community_Star_1
    state: present

- name: set-vpn-community-star
  cp_mgmt_vpn_community_star:
    encryption_method: ikev2 only
    encryption_suite: custom
    ike_phase_1:
      data_integrity: sha1
      diffie_hellman_group: group 19
      encryption_algorithm: aes-128
    ike_phase_2:
      data_integrity: aes-xcbc
      encryption_algorithm: aes-gcm-128
    name: New_VPN_Community_Star_1
    state: present

- name: delete-vpn-community-star
  cp_mgmt_vpn_community_star:
    name: New_VPN_Community_Star_1
    state: absent
"""

RETURN = """
cp_mgmt_vpn_community_star:
  description: The checkpoint object created or updated.
  returned: always, except when deleting the object.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import (
    checkpoint_argument_spec_for_objects,
    api_call,
)


def main():
    argument_spec = dict(
        name=dict(type="str", required=True),
        center_gateways=dict(type="list", elements="str"),
        encryption_method=dict(
            type="str",
            choices=[
                "prefer ikev2 but support ikev1",
                "ikev2 only",
                "ikev1 for ipv4 and ikev2 for ipv6 only",
            ],
        ),
        encryption_suite=dict(
            type="str",
            choices=[
                "suite-b-gcm-256",
                "custom",
                "vpn b",
                "vpn a",
                "suite-b-gcm-128",
            ],
        ),
        granular_encryptions=dict(type='list', elements="dict", options=dict(
            internal_gateway=dict(type='str'),
            external_gateway=dict(type='str'),
            encryption_method=dict(type='str', choices=['prefer ikev2 but support ikev1', 'ikev2 only',
                                                        'ikev1 for ipv4 and ikev2 for ipv6 only']),
            encryption_suite=dict(type='str',
                                  choices=['suite-b-gcm-256', 'custom', 'vpn b', 'vpn a', 'suite-b-gcm-128']),
            ike_phase_1=dict(type='dict', options=dict(
                encryption_algorithm=dict(type='str', choices=['cast', 'aes-256', 'des', 'aes-128', '3des']),
                data_integrity=dict(type='str', choices=['aes-xcbc', 'sha1', 'sha256', 'sha384', 'sha512', 'md5']),
                diffie_hellman_group=dict(type='str', choices=['group-1', 'group-2', 'group-5',
                                                               'group-14', 'group-15', 'group-16', 'group-17',
                                                               'group-18', 'group-19', 'group-20',
                                                               'group-24']),
                ike_p1_rekey_time=dict(type='int'),
                ike_p1_rekey_time_unit=dict(type='str', choices=['days', 'hours', 'minutes', 'seconds'])
            )),
            ike_phase_2=dict(type='dict', options=dict(
                encryption_algorithm=dict(type='str', choices=['cast', 'aes-gcm-256', 'cast-40',
                                                               'aes-256', 'des', 'aes-128', '3des', 'des-40cp',
                                                               'aes-gcm-128', 'none']),
                data_integrity=dict(type='str', choices=['aes-xcbc', 'sha1', 'sha256', 'sha384', 'sha512', 'md5']),
                ike_p2_use_pfs=dict(type='bool'),
                ike_p2_pfs_dh_grp=dict(type='str', choices=['group-1', 'group-2', 'group-5',
                                                            'group-14', 'group-15', 'group-16', 'group-17', 'group-18',
                                                            'group-19', 'group-20', 'group-24']),
                ike_p2_rekey_time=dict(type='int'),
                ike_p2_rekey_time_unit=dict(type='str', choices=['days', 'hours', 'minutes', 'seconds']),
            ))
        )),
        ike_phase_1=dict(
            type="dict",
            options=dict(
                data_integrity=dict(
                    type="str",
                    choices=["aes-xcbc", "sha1", "sha256", "sha384", "md5"],
                ),
                diffie_hellman_group=dict(
                    type="str",
                    choices=[
                        "group-1",
                        "group-2",
                        "group-5",
                        "group-14",
                        "group-19",
                        "group-20",
                    ],
                ),
                encryption_algorithm=dict(
                    type="str",
                    choices=["cast", "aes-256", "des", "aes-128", "3des"],
                ),
                ike_p1_rekey_time=dict(type='int'),
                ike_p1_rekey_time_unit=dict(type='str', choices=['days', 'hours', 'minutes', 'seconds']),
            ),
        ),
        ike_phase_2=dict(
            type="dict",
            options=dict(
                data_integrity=dict(
                    type="str",
                    choices=["aes-xcbc", "sha1", "sha256", "sha384", "md5"],
                ),
                encryption_algorithm=dict(
                    type="str",
                    choices=[
                        "cast",
                        "aes-gcm-256",
                        "cast-40",
                        "aes-256",
                        "des",
                        "aes-128",
                        "3des",
                        "des-40cp",
                        "aes-gcm-128",
                        "none",
                    ],
                ),
                ike_p2_use_pfs=dict(type='bool'),
                ike_p2_pfs_dh_grp=dict(type='str', choices=['group-1', 'group-2', 'group-5', 'group-14',
                                                            'group-15', 'group-16', 'group-17', 'group-18', 'group-19',
                                                            'group-20', 'group-24']),
                ike_p2_rekey_time=dict(type='int'),
                ike_p2_rekey_time_unit=dict(type='str', choices=['days', 'hours', 'minutes', 'seconds']),
            ),
        ),
        mesh_center_gateways=dict(type="bool"),
        override_vpn_domains=dict(type='list', elements="dict", options=dict(
            gateway=dict(type='str'),
            vpn_domain=dict(type='str')
        )),
        satellite_gateways=dict(type="list", elements="str"),
        shared_secrets=dict(
            type="list",
            elements="dict",
            no_log=True,
            options=dict(
                external_gateway=dict(type="str"),
                shared_secret=dict(type="str", no_log=True),
            ),
        ),
        tags=dict(type="list", elements="str"),
        tunnel_granularity=dict(type='str', choices=['per_host', 'per_subnet', 'universal']),
        use_shared_secret=dict(type="bool"),
        color=dict(
            type="str",
            choices=[
                "aquamarine",
                "black",
                "blue",
                "crete blue",
                "burlywood",
                "cyan",
                "dark green",
                "khaki",
                "orchid",
                "dark orange",
                "dark sea green",
                "pink",
                "turquoise",
                "dark blue",
                "firebrick",
                "brown",
                "forest green",
                "gold",
                "dark gold",
                "gray",
                "dark gray",
                "light green",
                "lemon chiffon",
                "coral",
                "sea green",
                "sky blue",
                "magenta",
                "purple",
                "slate blue",
                "violet red",
                "navy blue",
                "olive",
                "orange",
                "red",
                "sienna",
                "yellow",
            ],
        ),
        comments=dict(type="str"),
        details_level=dict(type="str", choices=["uid", "standard", "full"]),
        ignore_warnings=dict(type="bool"),
        ignore_errors=dict(type="bool"),
    )
    argument_spec.update(checkpoint_argument_spec_for_objects)

    module = AnsibleModule(
        argument_spec=argument_spec, supports_check_mode=True
    )
    api_call_object = "vpn-community-star"

    result = api_call(module, api_call_object)
    module.exit_json(**result)


if __name__ == "__main__":
    main()

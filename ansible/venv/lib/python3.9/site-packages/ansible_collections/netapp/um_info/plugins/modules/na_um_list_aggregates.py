#!/usr/bin/python

# (c) 2020, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_um_list_aggregates
'''

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}


DOCUMENTATION = '''
module: na_um_aggregates_info
short_description: NetApp Unified Manager list aggregates.
extends_documentation_fragment:
    - netapp.um_info.netapp.um
version_added: '20.5.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansibleteam@netapp.com>

description:
- List Aggregates on AIQUM.
'''

EXAMPLES = """
- name: List Aggregates
  netapp.um_info.na_um_aggregates_info:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
"""

RETURN = """
records:
    description: Returns list of Aggregates information
    returned: always
    type: list
    sample: [{'node':
                {'_links':
                    {'self':
                        {'href': '...'
                        }
                    },
                    'uuid': '...',
                    'key': '...',
                    'name': '...'
                },
                'snaplock_type': '...',
                'uuid': '...',
                'space':
                    {'block_storage':
                        {'available': ...,
                        'used': ...,
                        'size': ...
                        },
                    'efficiency':
                        {'savings': ...,
                        'logical_used': ...
                        }
                    },
                'block_storage':
                    {'hybrid_cache':
                        {'enabled': ...,
                        'size': ...
                        },
                    'primary':
                        {'raid_size': ...,
                        'raid_type': '...'
                        },
                    'mirror':
                        {'state': '...'
                        }
                    },
                'data_encryption':
                    {'software_encryption_enabled': ...
                    },
                'cluster':
                    {'_links':
                        {'self':
                            {'href': '...'
                            }
                        },
                    'uuid': '...',
                    'key': '...',
                    'name': '...'
                    },
                'state': '...',
                'create_time': '...',
                '_links':
                    {'self':
                        {'href': '...'
                        }
                    },
                'key': '...',
                'type': '...',
                'name': '...'
                }
            ]
"""

from ansible.module_utils.basic import AnsibleModule
import ansible_collections.netapp.um_info.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.um_info.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.um_info.plugins.module_utils.netapp import UMRestAPI


class NetAppUMAggregate(object):
    ''' aggregates initialize and class methods '''

    def __init__(self):
        self.argument_spec = netapp_utils.na_um_host_argument_spec()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        self.rest_api = UMRestAPI(self.module)

    def get_aggregates(self):
        """
        Fetch details of aggregates.
        :return:
            Dictionary of current details if aggregates found
            None if aggregates is not found
        """
        data = {}
        api = "datacenter/storage/aggregates?order_by=performance_capacity.used"
        message, error = self.rest_api.get(api, data)
        if error:
            self.module.fail_json(msg=error)
        return self.rest_api.get_records(message, api)

    def apply(self):
        """
        Apply action to the aggregates listing
        :return: None
        """
        current = self.get_aggregates()
        if current is not None:
            self.na_helper.changed = True
        self.module.exit_json(changed=self.na_helper.changed, msg=current)


def main():
    """
    Create Aggregate class instance and invoke apply
    :return: None
    """
    list_aggregates_obj = NetAppUMAggregate()
    list_aggregates_obj.apply()


if __name__ == '__main__':
    main()

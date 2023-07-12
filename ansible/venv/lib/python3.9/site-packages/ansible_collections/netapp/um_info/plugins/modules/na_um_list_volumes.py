#!/usr/bin/python

# (c) 2020, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_um_list_volumes
'''

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}


DOCUMENTATION = '''
module: na_um_volumes_info
short_description: NetApp Unified Manager list volumes.
extends_documentation_fragment:
    - netapp.um_info.netapp.um
version_added: '20.6.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansibleteam@netapp.com>

description:
- List Volumes on AIQUM.
'''

EXAMPLES = """
- name: List Volumes
  netapp.um_info.na_um_volumes_info:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
"""

RETURN = """
records:
    description: Returns list of Volumes information
    returned: always
    type: list
    sample: [{'style': '...',
              'svm':
                {'_links':
                    {'self': {...}
                    },
                '...'
                },
              'qos': {...},
              'name': '...',
              'language': '...',
              'space': {...},
              'aggregates':
                [
                    {...}
                ],
              'tiering': {...},
              'autosize': {...},
              'cluster': {...},
              'state': '...',
              'create_time': '...',
              '_links':
                {'self':
                    {'href': '...'
                    }
                },
              'key': '...',
              'snapmirror': {...},
              'snapshot_policy': {...},
              'type': '...',
              'uuid': '...'
              }]
"""

from ansible.module_utils.basic import AnsibleModule
import ansible_collections.netapp.um_info.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.um_info.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.um_info.plugins.module_utils.netapp import UMRestAPI


class NetAppUMVolume(object):
    ''' volumes initialize and class methods '''

    def __init__(self):
        self.argument_spec = netapp_utils.na_um_host_argument_spec()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        self.rest_api = UMRestAPI(self.module)

    def get_volumes(self):
        """
        Fetch details of volumes.
        :return:
            Dictionary of current details if volumes found
            None if volumes is not found
        """
        data = {}
        api = "datacenter/storage/volumes"
        message, error = self.rest_api.get(api, data)
        if error:
            self.module.fail_json(msg=error)
        return self.rest_api.get_records(message, api)

    def apply(self):
        """
        Apply action to the volumes listing
        :return: None
        """
        current = self.get_volumes()
        if current is not None:
            self.na_helper.changed = True
        self.module.exit_json(changed=self.na_helper.changed, msg=current)


def main():
    """
    Create Volume class instance and invoke apply
    :return: None
    """
    list_volumes_obj = NetAppUMVolume()
    list_volumes_obj.apply()


if __name__ == '__main__':
    main()

#!/usr/bin/python

# (c) 2020, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_um_list_clusters
'''

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}


DOCUMENTATION = '''
module: na_um_clusters_info
short_description: NetApp Unified Manager list cluster.
extends_documentation_fragment:
    - netapp.um_info.netapp.um
version_added: '20.5.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansibleteam@netapp.com>

description:
- List Cluster on AIQUM.
'''

EXAMPLES = """
- name: List Clusters
  netapp.um_info.na_um_clusters_info:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
"""

RETURN = """
records:
    description: Returns list of Clusters information
    returned: always
    type: list
    sample: [{
            'name': '...',
            'version':
                {
                'generation': ...,
                'major': ...,
                'full': '...',
                'minor': ...
                },
            'management_ip': '...',
            'contact': ...,
            '_links':
                {
                'self':
                    {
                    'href': '...'
                    }
                },
            'location': '...',
            'key': '',
            'nodes':
                [
                {
                'uptime': ...,
                'uuid': '...',
                'version':
                    {
                    'generation': ...,
                    'major': ...,
                    'full': '...',
                    'minor': ...
                    },
                '_links':
                    {
                    'self':
                        {
                        'href': '...'
                        }
                    },
                'location': '...',
                'key': '...',
                'serial_number': '...',
                'model': '...',
                'name': '...'
                }
                ],
            'isSanOptimized': ...,
            'uuid': '...'
            }
            ]
"""

from ansible.module_utils.basic import AnsibleModule
import ansible_collections.netapp.um_info.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.um_info.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.um_info.plugins.module_utils.netapp import UMRestAPI


class NetAppUMCluster(object):
    ''' cluster initialize and class methods '''

    def __init__(self):
        self.argument_spec = netapp_utils.na_um_host_argument_spec()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        self.rest_api = UMRestAPI(self.module)

    def get_clusters(self):
        """
        Fetch details of clusters.
        :return:
            Dictionary of current details if clusters found
            None if clusters is not found
        """
        data = {}
        api = "datacenter/cluster/clusters"
        message, error = self.rest_api.get(api, data)
        if error:
            self.module.fail_json(msg=error)
        return self.rest_api.get_records(message, api)

    def apply(self):
        """
        Apply action to the cluster listing
        :return: None
        """
        current = self.get_clusters()
        if current is not None:
            self.na_helper.changed = True
        self.module.exit_json(changed=self.na_helper.changed, msg=current)


def main():
    """
    Create Cluster class instance and invoke apply
    :return: None
    """
    list_cluster_obj = NetAppUMCluster()
    list_cluster_obj.apply()


if __name__ == '__main__':
    main()

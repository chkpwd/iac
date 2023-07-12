#!/usr/bin/python

# (c) 2020, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_um_list_svms
'''

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}


DOCUMENTATION = '''
module: na_um_svms_info
short_description: NetApp Unified Manager list svms.
extends_documentation_fragment:
    - netapp.um_info.netapp.um
version_added: '20.5.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansibleteam@netapp.com>

description:
- List SVMs on AIQUM.
'''

EXAMPLES = """
- name: List SVMs
  netapp.um_info.na_um_svms_info:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
"""

RETURN = """
records:
    description: Returns list of SVMs information
    returned: always
    type: list
    sample: [{'fcp':
                {'enabled': ...
                },
            'dns': ...,
            'snapshot_policy':
                {'_links': {},
                'uuid': ...,
                'key': '...',
                'name': '...'
                },
            'language': '...',
            'subtype': 'default',
            'aggregates':
                [{'_links':
                    {'self':
                        {'href': '...'
                        }
                    },
                'uuid': '...',
                'key': '...',
                'name': '...'
                }],
            'nvme':
                {'enabled': ...
                },
            'ipspace':
                {'_links': {},
                'uuid': '...',
                'key': '...',
                'name': '...'
                },
            'uuid': '...',
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
            '_links':
                {'self':
                    {'href': '...'
                    }
                },
            'key': '...',
            'ldap':
                {'enabled': ...
                },
            'nis':
                {'domain': ...,
                'enabled': ...,
                'servers': ...
                },
            'cifs':
                {'enabled': ...,
                'name': ...,
                'ad_domain':
                    {'fqdn': ...
                    }
                },
            'iscsi':
                {'enabled': ...
                },
            'nfs':
                {'enabled': ...
                },
            'name': '...'
            }]
"""

from ansible.module_utils.basic import AnsibleModule
import ansible_collections.netapp.um_info.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.um_info.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.um_info.plugins.module_utils.netapp import UMRestAPI


class NetAppUMSVM(object):
    ''' svms initialize and class methods '''

    def __init__(self):
        self.argument_spec = netapp_utils.na_um_host_argument_spec()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        self.rest_api = UMRestAPI(self.module)

    def get_svms(self):
        """
        Fetch details of svms.
        :return:
            Dictionary of current details if svms found
            None if svms is not found
        """
        data = {}
        api = "datacenter/svm/svms"
        message, error = self.rest_api.get(api, data)
        if error:
            self.module.fail_json(msg=error)
        return self.rest_api.get_records(message, api)

    def apply(self):
        """
        Apply action to the svms listing
        :return: None
        """
        current = self.get_svms()
        if current is not None:
            self.na_helper.changed = True
        self.module.exit_json(changed=self.na_helper.changed, msg=current)


def main():
    """
    Create SVM class instance and invoke apply
    :return: None
    """
    list_svms_obj = NetAppUMSVM()
    list_svms_obj.apply()


if __name__ == '__main__':
    main()

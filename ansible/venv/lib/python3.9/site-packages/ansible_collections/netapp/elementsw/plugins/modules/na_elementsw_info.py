#!/usr/bin/python
# (c) 2020, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
Element Software Info
'''
from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}


DOCUMENTATION = '''

module: na_elementsw_info
short_description: NetApp Element Software Info
extends_documentation_fragment:
  - netapp.elementsw.netapp.solidfire
version_added: 20.10.0
author: NetApp Ansible Team (@carchi8py) <ng-ansibleteam@netapp.com>
description:
  - Collect cluster and node information.
  - Use a MVIP as hostname for cluster and node scope.
  - Use a MIP as hostname for node scope.
  - When using MIPs, cluster APIs are expected to fail with 'xUnknownAPIMethod  method=ListAccounts'

options:
  gather_subsets:
    description:
      - list of subsets to gather from target cluster or node
      - supported values
      - node_config, cluster_accounts, cluster_nodes, cluster_drives.
      - additional values
      - all - for all subsets,
      - all_clusters - all subsets at cluster scope,
      - all_nodes - all subsets at node scope
    type: list
    elements: str
    default: ['all']
    aliases: ['gather_subset']

  filter:
    description:
      - When a list of records is returned, this can be used to limit the records to be returned.
      - If more than one key is used, all keys must match.
    type: dict

  fail_on_error:
    description:
      - by default, errors are not fatal when collecting a subset.  The subset will show on error in the info output.
      - if set to True, the module fails on the first error.
    type: bool
    default: false

  fail_on_key_not_found:
    description:
      - force an error when filter is used and a key is not present in records.
    type: bool
    default: true

  fail_on_record_not_found:
    description:
      - force an error when filter is used and no record is matched.
    type: bool
    default: false
'''

EXAMPLES = """

  - name: get all available subsets
    na_elementsw_info:
      hostname: "{{ elementsw_mvip }}"
      username: "{{ elementsw_username }}"
      password: "{{ elementsw_password }}"
      gather_subsets: all
    register: result

  - name: collect data for elementsw accounts using a filter
    na_elementsw_info:
      hostname: "{{ elementsw_mvip }}"
      username: "{{ elementsw_username }}"
      password: "{{ elementsw_password }}"
      gather_subsets: 'cluster_accounts'
      filter:
        username: "{{ username_to_find }}"
    register: result
"""

RETURN = """

info:
  description:
    - a dictionary of collected subsets
    - each subset if in JSON format
  returned: success
  type: dict

debug:
  description:
    - a list of detailed error messages if some subsets cannot be collected
  returned: success
  type: list

"""
from ansible.module_utils.basic import AnsibleModule

import ansible_collections.netapp.elementsw.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.elementsw.plugins.module_utils.netapp_module import NetAppModule

HAS_SF_SDK = netapp_utils.has_sf_sdk()


class ElementSWInfo(object):
    '''
    Element Software Initialize node with ownership for cluster formation
    '''

    def __init__(self):
        self.argument_spec = netapp_utils.ontap_sf_host_argument_spec()
        self.argument_spec.update(dict(
            gather_subsets=dict(type='list', elements='str', aliases=['gather_subset'], default='all'),
            filter=dict(type='dict'),
            fail_on_error=dict(type='bool', default=False),
            fail_on_key_not_found=dict(type='bool', default=True),
            fail_on_record_not_found=dict(type='bool', default=False),
        ))
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.debug = list()

        if HAS_SF_SDK is False:
            self.module.fail_json(msg="Unable to import the SolidFire Python SDK")

        # 442 for node APIs, 443 (default) for cluster APIs
        for role, port in [('node', 442), ('cluster', 443)]:
            try:
                conn = netapp_utils.create_sf_connection(module=self.module, raise_on_connection_error=True, port=port)
                if role == 'node':
                    self.sfe_node = conn
                else:
                    self.sfe_cluster = conn
            except netapp_utils.solidfire.common.ApiConnectionError as exc:
                if str(exc) == "Bad Credentials":
                    msg = ' Make sure to use valid %s credentials for username and password.' % 'node' if port == 442 else 'cluster'
                    msg += '%s reported: %s' % ('Node' if port == 442 else 'Cluster', repr(exc))
                else:
                    msg = 'Failed to create connection for %s:%d - %s' % (self.parameters['hostname'], port, repr(exc))
                self.module.fail_json(msg=msg)
            except Exception as exc:
                self.module.fail_json(msg='Failed to connect for %s:%d - %s' % (self.parameters['hostname'], port, repr(exc)))

        # TODO: add new node methods here
        self.node_methods = dict(
            node_config=self.sfe_node.get_config,
        )
        # TODO: add new cluster methods here
        self.cluster_methods = dict(
            cluster_accounts=self.sfe_cluster.list_accounts,
            cluster_drives=self.sfe_cluster.list_drives,
            cluster_nodes=self.sfe_cluster.list_all_nodes
        )
        self.methods = dict(self.node_methods)
        self.methods.update(self.cluster_methods)

        # add telemetry attributes - does not matter if we are using cluster or node here
        # TODO: most if not all get and list APIs do not have an attributes parameter

    def get_info(self, name):
        '''
        Get Element Info
            run a cluster or node list method
            return output as json
        '''
        info = None
        if name not in self.methods:
            msg = 'Error: unknown subset %s.' % name
            msg += '  Known_subsets: %s' % ', '.join(self.methods.keys())
            self.module.fail_json(msg=msg, debug=self.debug)
        try:
            info = self.methods[name]()
            return info.to_json()
        except netapp_utils.solidfire.common.ApiServerError as exc:
            # the new SDK rearranged the fields in a different order
            if all(x in str(exc) for x in ('err_json', '500', 'xUnknownAPIMethod', 'method=')):
                info = 'Error (API not in scope?)'
            else:
                info = 'Error'
            msg = '%s for subset: %s: %s' % (info, name, repr(exc))
            if self.parameters['fail_on_error']:
                self.module.fail_json(msg=msg)
            self.debug.append(msg)
        return info

    def filter_list_of_dict_by_key(self, records, key, value):
        matched = list()
        for record in records:
            if key in record and record[key] == value:
                matched.append(record)
            if key not in record and self.parameters['fail_on_key_not_found']:
                msg = 'Error: key %s not found in %s' % (key, repr(record))
                self.module.fail_json(msg=msg)
        return matched

    def filter_records(self, records, filter_dict):

        if isinstance(records, dict):
            if len(records) == 1:
                key, value = list(records.items())[0]
                return dict({key: self.filter_records(value, filter_dict)})
        if not isinstance(records, list):
            return records
        matched = records
        for key, value in filter_dict.items():
            matched = self.filter_list_of_dict_by_key(matched, key, value)
        if self.parameters['fail_on_record_not_found'] and len(matched) == 0:
            msg = 'Error: no match for %s out of %d records' % (repr(self.parameters['filter']), len(records))
            self.debug.append('Unmatched records: %s' % repr(records))
            self.module.fail_json(msg=msg, debug=self.debug)
        return matched

    def get_and_filter_info(self, name):
        '''
        Get data
        If filter is present, only return the records that are matched
        return output as json
        '''
        records = self.get_info(name)
        if self.parameters.get('filter') is None:
            return records
        matched = self.filter_records(records, self.parameters.get('filter'))
        return matched

    def apply(self):
        '''
        Check connection and initialize node with cluster ownership
        '''
        changed = False
        info = dict()
        my_subsets = ('all', 'all_clusters', 'all_nodes')
        if any(x in self.parameters['gather_subsets'] for x in my_subsets) and len(self.parameters['gather_subsets']) > 1:
            msg = 'When any of %s is used, no other subset is allowed' % repr(my_subsets)
            self.module.fail_json(msg=msg)
        if 'all' in self.parameters['gather_subsets']:
            self.parameters['gather_subsets'] = self.methods.keys()
        if 'all_clusters' in self.parameters['gather_subsets']:
            self.parameters['gather_subsets'] = self.cluster_methods.keys()
        if 'all_nodes' in self.parameters['gather_subsets']:
            self.parameters['gather_subsets'] = self.node_methods.keys()
        for name in self.parameters['gather_subsets']:
            info[name] = self.get_and_filter_info(name)
        self.module.exit_json(changed=changed, info=info, debug=self.debug)


def main():
    '''
    Main function
    '''
    na_elementsw_cluster = ElementSWInfo()
    na_elementsw_cluster.apply()


if __name__ == '__main__':
    main()

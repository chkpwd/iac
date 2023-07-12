#!/usr/bin/python
# (c) 2018, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

'''
Element Software Node Operation
'''
from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}


DOCUMENTATION = '''

module: na_elementsw_node

short_description: NetApp Element Software Node Operation
extends_documentation_fragment:
    - netapp.elementsw.netapp.solidfire
version_added: 2.7.0
author: NetApp Ansible Team (@carchi8py) <ng-ansibleteam@netapp.com>
description:
    - Add, remove cluster node on Element Software Cluster.
    - Set cluster name on node.
    - When using the preset_only option, hostname/username/password are required but not used.

options:
    state:
        description:
        - Element Software Storage Node operation state.
        - present - To add pending node to participate in cluster data storage.
        - absent  - To remove node from active cluster.  A node cannot be removed if active drives are present.
        choices: ['present', 'absent']
        default: 'present'
        type: str

    node_ids:
        description:
          - List of IDs or Names or IP Addresses of nodes to add or remove.
          - If cluster_name is set, node MIPs are required.
        type: list
        elements: str
        required: true
        aliases: ['node_id']

    cluster_name:
        description:
          - If set, the current node configuration is updated with this name before adding the node to the cluster.
          - This requires the node_ids to be specified as MIPs (Management IP Adresses)
        type: str
        version_added: 20.9.0

    preset_only:
        description:
          - If true and state is 'present', set the cluster name for each node in node_ids, but do not add the nodes.
          - They can be added using na_elementsw_cluster for initial cluster creation.
          - If false, proceed with addition/removal.
        type: bool
        default: false
        version_added: 20.9.0
'''

EXAMPLES = """
   - name: Add node from pending to active cluster
     tags:
     - elementsw_add_node
     na_elementsw_node:
       hostname: "{{ elementsw_hostname }}"
       username: "{{ elementsw_username }}"
       password: "{{ elementsw_password }}"
       state: present
       node_id: sf4805-meg-03

   - name: Remove active node from cluster
     tags:
     - elementsw_remove_node
     na_elementsw_node:
       hostname: "{{ elementsw_hostname }}"
       username: "{{ elementsw_username }}"
       password: "{{ elementsw_password }}"
       state: absent
       node_id: 13

   - name: Add node from pending to active cluster using node IP
     tags:
     - elementsw_add_node_ip
     na_elementsw_node:
       hostname: "{{ elementsw_hostname }}"
       username: "{{ elementsw_username }}"
       password: "{{ elementsw_password }}"
       state: present
       node_id: 10.109.48.65
       cluster_name: sfcluster01

   - name: Only set cluster name
     tags:
     - elementsw_add_node_ip
     na_elementsw_node:
       hostname: "{{ elementsw_hostname }}"
       username: "{{ elementsw_username }}"
       password: "{{ elementsw_password }}"
       state: present
       node_ids: 10.109.48.65,10.109.48.66
       cluster_name: sfcluster01
       preset_only: true
"""


RETURN = """

msg:
    description: Success message
    returned: success
    type: str

"""
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.elementsw.plugins.module_utils.netapp as netapp_utils


HAS_SF_SDK = netapp_utils.has_sf_sdk()


class ElementSWNode(object):
    """
    Element SW Storage Node operations
    """

    def __init__(self):
        self.argument_spec = netapp_utils.ontap_sf_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, choices=['present', 'absent'], default='present'),
            node_ids=dict(required=True, type='list', elements='str', aliases=['node_id']),
            cluster_name=dict(required=False, type='str'),
            preset_only=dict(required=False, type='bool', default=False),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        input_params = self.module.params

        self.state = input_params['state']
        self.node_ids = input_params['node_ids']
        self.cluster_name = input_params['cluster_name']
        self.preset_only = input_params['preset_only']

        if HAS_SF_SDK is False:
            self.module.fail_json(
                msg="Unable to import the SolidFire Python SDK")
        elif not self.preset_only:
            # Cluster connection is only needed for add/delete operations
            self.sfe = netapp_utils.create_sf_connection(module=self.module)

    def check_node_has_active_drives(self, node_id=None):
        """
            Check if node has active drives attached to cluster
            :description: Validate if node have active drives in cluster

            :return: True or False
            :rtype: bool
        """
        if node_id is not None:
            cluster_drives = self.sfe.list_drives()
            for drive in cluster_drives.drives:
                if drive.node_id == node_id and drive.status == "active":
                    return True
        return False

    @staticmethod
    def extract_node_info(node_list):
        summary = list()
        for node in node_list:
            node_dict = dict()
            for key, value in vars(node).items():
                if key in ['assigned_node_id', 'cip', 'mip', 'name', 'node_id', 'pending_node_id', 'sip']:
                    node_dict[key] = value
            summary.append(node_dict)
        return summary

    def get_node_list(self):
        """
            Get Node List
            :description: Find and retrieve node_ids from the active cluster

            :return: None
            :rtype: None
        """
        action_nodes_list = list()
        if len(self.node_ids) > 0:
            unprocessed_node_list = list(self.node_ids)
            list_nodes = []
            try:
                all_nodes = self.sfe.list_all_nodes()
            except netapp_utils.solidfire.common.ApiServerError as exception_object:
                self.module.fail_json(msg='Error getting list of nodes from cluster: %s' % to_native(exception_object),
                                      exception=traceback.format_exc())

            # For add operation lookup for nodes list with status pendingNodes list
            # else nodes will have to be traverse through active cluster
            if self.state == "present":
                list_nodes = all_nodes.pending_nodes
            else:
                list_nodes = all_nodes.nodes

            for current_node in list_nodes:
                if self.state == "absent" and \
                   (str(current_node.node_id) in self.node_ids or current_node.name in self.node_ids or current_node.mip in self.node_ids):
                    if self.check_node_has_active_drives(current_node.node_id):
                        self.module.fail_json(msg='Error deleting node %s: node has active drives' % current_node.name)
                    else:
                        action_nodes_list.append(current_node.node_id)
                if self.state == "present" and \
                   (str(current_node.pending_node_id) in self.node_ids or current_node.name in self.node_ids or current_node.mip in self.node_ids):
                    action_nodes_list.append(current_node.pending_node_id)

            # report an error if state == present and node is unknown
            if self.state == "present":
                for current_node in all_nodes.nodes:
                    if str(current_node.node_id) in unprocessed_node_list:
                        unprocessed_node_list.remove(str(current_node.node_id))
                    elif current_node.name in unprocessed_node_list:
                        unprocessed_node_list.remove(current_node.name)
                    elif current_node.mip in unprocessed_node_list:
                        unprocessed_node_list.remove(current_node.mip)
                for current_node in all_nodes.pending_nodes:
                    if str(current_node.pending_node_id) in unprocessed_node_list:
                        unprocessed_node_list.remove(str(current_node.pending_node_id))
                    elif current_node.name in unprocessed_node_list:
                        unprocessed_node_list.remove(current_node.name)
                    elif current_node.mip in unprocessed_node_list:
                        unprocessed_node_list.remove(current_node.mip)
                if len(unprocessed_node_list) > 0:
                    summary = dict(
                        nodes=self.extract_node_info(all_nodes.nodes),
                        pending_nodes=self.extract_node_info(all_nodes.pending_nodes),
                        pending_active_nodes=self.extract_node_info(all_nodes.pending_active_nodes)
                    )
                    self.module.fail_json(msg='Error adding nodes %s: nodes not in pending or active lists: %s' %
                                          (to_native(unprocessed_node_list), repr(summary)))
        return action_nodes_list

    def add_node(self, nodes_list=None):
        """
        Add Node  that are on PendingNodes list available on Cluster
        """
        try:
            self.sfe.add_nodes(nodes_list, auto_install=True)
        except Exception as exception_object:
            self.module.fail_json(msg='Error adding nodes %s to cluster: %s' % (nodes_list, to_native(exception_object)),
                                  exception=traceback.format_exc())

    def remove_node(self, nodes_list=None):
        """
        Remove active node from Cluster
        """
        try:
            self.sfe.remove_nodes(nodes_list)
        except Exception as exception_object:
            self.module.fail_json(msg='Error removing nodes %s from cluster  %s' % (nodes_list, to_native(exception_object)),
                                  exception=traceback.format_exc())

    def set_cluster_name(self, node):
        ''' set up cluster name for the node using its MIP '''
        cluster = dict(cluster=self.cluster_name)
        port = 442
        try:
            node_cx = netapp_utils.create_sf_connection(module=self.module, raise_on_connection_error=True, hostname=node, port=port)
        except netapp_utils.solidfire.common.ApiConnectionError as exc:
            if str(exc) == "Bad Credentials":
                msg = 'Most likely the node %s is already in a cluster.' % node
                msg += '  Make sure to use valid node credentials for username and password.'
                msg += '  Node reported: %s' % repr(exc)
            else:
                msg = 'Failed to create connection: %s' % repr(exc)
            self.module.fail_json(msg=msg)
        except Exception as exc:
            self.module.fail_json(msg='Failed to connect to %s:%d - %s' % (node, port, to_native(exc)),
                                  exception=traceback.format_exc())

        try:
            cluster_config = node_cx.get_cluster_config()
        except netapp_utils.solidfire.common.ApiServerError as exc:
            self.module.fail_json(msg='Error getting cluster config: %s' % to_native(exc),
                                  exception=traceback.format_exc())

        if cluster_config.cluster.cluster == self.cluster_name:
            return False
        if cluster_config.cluster.state == 'Active':
            self.module.fail_json(msg="Error updating cluster name for node %s, already in 'Active' state"
                                  % node, cluster_config=repr(cluster_config))
        if self.module.check_mode:
            return True

        try:
            node_cx.set_cluster_config(cluster)
        except netapp_utils.solidfire.common.ApiServerError as exc:
            self.module.fail_json(msg='Error updating cluster name: %s' % to_native(exc),
                                  cluster_config=repr(cluster_config),
                                  exception=traceback.format_exc())
        return True

    def apply(self):
        """
        Check, process and initiate Cluster Node operation
        """
        changed = False
        updated_nodes = list()
        result_message = ''
        if self.state == "present" and self.cluster_name is not None:
            for node in self.node_ids:
                if self.set_cluster_name(node):
                    changed = True
                    updated_nodes.append(node)
        if not self.preset_only:
            # let's see if there is anything to add or remove
            action_nodes_list = self.get_node_list()
            action = None
            if self.state == "present" and len(action_nodes_list) > 0:
                changed = True
                action = 'added'
                if not self.module.check_mode:
                    self.add_node(action_nodes_list)
            elif self.state == "absent" and len(action_nodes_list) > 0:
                changed = True
                action = 'removed'
                if not self.module.check_mode:
                    self.remove_node(action_nodes_list)
            if action:
                result_message = 'List of %s nodes: %s - requested: %s' % (action, to_native(action_nodes_list), to_native(self.node_ids))
        if updated_nodes:
            result_message += '\n' if result_message else ''
            result_message += 'List of updated nodes with %s: %s' % (self.cluster_name, updated_nodes)
        self.module.exit_json(changed=changed, msg=result_message)


def main():
    """
    Main function
    """

    na_elementsw_node = ElementSWNode()
    na_elementsw_node.apply()


if __name__ == '__main__':
    main()

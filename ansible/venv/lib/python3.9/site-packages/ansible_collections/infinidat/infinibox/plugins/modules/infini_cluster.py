#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Infinidat <info@infinidat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: infini_cluster
version_added: '2.9.0'
short_description: Create, Delete and Modify Host Cluster on Infinibox
description:
    - This module creates, deletes or modifies host clusters on Infinibox.
author: David Ohlemacher (@ohlemacher)
options:
  name:
    description:
      - Cluster Name
    required: true
    type: str
  state:
    description:
      - Creates/Modifies Cluster when present, removes when absent, or provides
        details of a cluster when stat.
    required: false
    type: str
    default: present
    choices: [ "stat", "present", "absent" ]
  cluster_hosts:
    description: A list of hosts to add to a cluster when state is present.
    required: false
    type: list
    elements: dict
extends_documentation_fragment:
    - infinibox
'''

EXAMPLES = r'''
- name: Create new cluster
  infini_cluster:
    name: foo_cluster
    user: admin
    password: secret
    system: ibox001
'''

# RETURN = r''' # '''

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

import traceback

try:
    from ansible_collections.infinidat.infinibox.plugins.module_utils.infinibox import (
        HAS_INFINISDK,
        INFINISDK_IMPORT_ERROR,
        api_wrapper,
        infinibox_argument_spec,
        get_system,
        get_cluster,
        unixMillisecondsToDate,
        merge_two_dicts,
    )
except ModuleNotFoundError:
    from infinibox import (  # Used when hacking
        HAS_INFINISDK,
        INFINISDK_IMPORT_ERROR,
        api_wrapper,
        infinibox_argument_spec,
        get_system,
        get_cluster,
        unixMillisecondsToDate,
        merge_two_dicts,
    )

try:
    from infi.dtypes.iqn import make_iscsi_name
    HAS_INFI_MOD = True
except ImportError:
    HAS_INFI_MOD = False


@api_wrapper
def get_host_by_name(system, host_name):
    """Find a host by the name specified in the module"""
    host = None

    for a_host in system.hosts.to_list():
        a_host_name = a_host.get_name()
        if a_host_name == host_name:
            host = a_host
            break
    return host


@api_wrapper
def create_cluster(module, system):
    # print("create cluster")
    changed = True
    if not module.check_mode:
        cluster = system.host_clusters.create(name=module.params['name'])
        cluster_hosts = module.params['cluster_hosts']
        for cluster_host in cluster_hosts:
            if cluster_host['host_cluster_state'] == 'present':
                host = get_host_by_name(system, cluster_host['host_name'])
                cluster.add_host(host)
            #     print("Added host {0} to cluster {1}".format(host.get_name, cluster.get_name()))
            # else:
            #     print("Skipped adding (absent) host {0} to cluster {1}".format(host.get_name, cluster.get_name()))
    return changed


@api_wrapper
def update_cluster(module, system, cluster):
    # print("update cluster")
    changed = False

    # e.g. of one host dict found in the module.params['cluster_hosts'] list:
    #    {host_name: <'some_name'>, host_cluster_state: <'present' or 'absent'>}
    module_cluster_hosts = module.params['cluster_hosts']
    current_cluster_hosts_names = [host.get_name() for host in cluster.get_field('hosts')]
    # print("current_cluster_hosts_names:", current_cluster_hosts_names)
    for module_cluster_host in module_cluster_hosts:
        module_cluster_host_name = module_cluster_host['host_name']
        # print("module_cluster_host_name:", module_cluster_host_name)
        # Need to add host to cluster?
        if module_cluster_host_name not in current_cluster_hosts_names:
            if module_cluster_host['host_cluster_state'] == 'present':
                host = get_host_by_name(system, module_cluster_host_name)
                if not host:
                    msg = 'Cannot find host {0} to add to cluster {1}'.format(
                        module_cluster_host_name,
                        cluster.get_name(),
                    )
                    module.fail_json(msg=msg)
                cluster.add_host(host)
                # print("Added host {0} to cluster {1}".format(host.get_name(), cluster.get_name()))
                changed = True
        # Need to remove host from cluster?
        elif module_cluster_host_name in current_cluster_hosts_names:
            if module_cluster_host['host_cluster_state'] == 'absent':
                host = get_host_by_name(system, module_cluster_host_name)
                if not host:
                    msg = 'Cannot find host {0} to add to cluster {1}'.format(
                        module_cluster_host_name,
                        cluster.get_name(),
                    )
                    module.fail_json(msg=msg)
                cluster.remove_host(host)
                # print("Removed host {0} from cluster {1}".format(host.get_name(), cluster.get_name()))
                changed = True
    return changed


@api_wrapper
def delete_cluster(module, cluster):
    if not cluster:
        msg = "Cluster {0} not found".format(cluster.get_name())
        module.fail_json(msg=msg)
    changed = True
    if not module.check_mode:
        cluster.delete()
    return changed


def get_sys_cluster(module):
    system = get_system(module)
    cluster = get_cluster(module, system)
    return (system, cluster)


def get_cluster_fields(cluster):
    fields = cluster.get_fields(from_cache=True, raw_value=True)
    created_at, created_at_timezone = unixMillisecondsToDate(fields.get('created_at', None))
    field_dict = dict(
        hosts=[],
        id=cluster.id,
        created_at=created_at,
        created_at_timezone=created_at_timezone,
    )
    hosts = cluster.get_hosts()
    for host in hosts:
        host_dict = {
            'host_id': host.id,
            'host_name': host.get_name(),
        }
        field_dict['hosts'].append(host_dict)
    return field_dict


def handle_stat(module):
    system, cluster = get_sys_cluster(module)
    cluster_name = module.params["name"]
    if not cluster:
        module.fail_json(msg='Cluster {0} not found'.format(cluster_name))
    field_dict = get_cluster_fields(cluster)
    result = dict(
        changed=False,
        msg='Cluster stat found'
    )
    result = merge_two_dicts(result, field_dict)
    module.exit_json(**result)


def handle_present(module):
    system, cluster = get_sys_cluster(module)
    cluster_name = module.params["name"]
    if not cluster:
        changed = create_cluster(module, system)
        msg = 'Cluster {0} created'.format(cluster_name)
        module.exit_json(changed=changed, msg=msg)
    else:
        changed = update_cluster(module, system, cluster)
        if changed:
            msg = 'Cluster {0} updated'.format(cluster_name)
        else:
            msg = 'Cluster {0} required no changes'.format(cluster_name)
        module.exit_json(changed=changed, msg=msg)


def handle_absent(module):
    system, cluster = get_sys_cluster(module)
    cluster_name = module.params["name"]
    if not cluster:
        changed = False
        msg = "Cluster {0} already absent".format(cluster_name)
    else:
        changed = delete_cluster(module, cluster)
        msg = "Cluster {0} removed".format(cluster_name)
    module.exit_json(changed=changed, msg=msg)


def execute_state(module):
    state = module.params['state']
    try:
        if state == 'stat':
            handle_stat(module)
        elif state == 'present':
            handle_present(module)
        elif state == 'absent':
            handle_absent(module)
        else:
            module.fail_json(msg='Internal handler error. Invalid state: {0}'.format(state))
    finally:
        system = get_system(module)
        system.logout()


def check_options(module):
    state = module.params['state']
    if state == 'present':
        if module.params['cluster_hosts'] is None:
            module.fail_json(msg='Option cluster_hosts, a list, must be provided')

        cluster_hosts = module.params['cluster_hosts']
        for host in cluster_hosts:
            try:
                # Check host has required keys
                valid_keys = ['host_name', 'host_cluster_state']
                for valid_key in valid_keys:
                    not_used = host[valid_key]
                # Check host has no unknown keys
                if len(host.keys()) != len(valid_keys):
                    raise KeyError
            except KeyError:
                msg = 'With state present, all cluster_hosts ' \
                    + 'require host_name and host_cluster_state key:values ' \
                    + 'and no others'
                module.fail_json(msg=msg)


def main():
    argument_spec = infinibox_argument_spec()
    argument_spec.update(
        dict(
            name=dict(required=True),
            state=dict(default='present', choices=['stat', 'present', 'absent']),
            cluster_hosts=dict(required=False, type="list", elements="dict"),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_INFI_MOD:
        module.fail_json(msg=missing_required_lib('infi.dtypes.iqn'))

    if not HAS_INFINISDK:
        module.fail_json(msg=missing_required_lib('infinisdk'))

    check_options(module)
    execute_state(module)


if __name__ == '__main__':
    main()

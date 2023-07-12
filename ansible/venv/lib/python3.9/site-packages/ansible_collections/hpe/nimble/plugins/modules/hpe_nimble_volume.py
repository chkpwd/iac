#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright 2020 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
# file except in compliance with the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
# OF ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.

# author Alok Ranjan (alok.ranjan2@hpe.com)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
author:
  - HPE Nimble Storage Ansible Team (@ar-india) <nimble-dcs-storage-automation-eng@hpe.com>
description: Manage the volumes on an HPE Nimble Storage group.
module: hpe_nimble_volume
options:
  agent_type:
    required: False
    choices:
    - none
    - smis
    - vvol
    - openstack
    - openstackv2
    type: str
    description:
    - External management agent type.
  app_uuid:
    required: False
    type: str
    description:
    - Application identifier of volume.
  block_size:
    required: False
    type: int
    description:
    - Size in bytes of blocks in the volume.
  cache_pinned:
    required: False
    type: bool
    description:
    - If set to true, all the contents of this volume are kept in flash cache.
  caching:
    required: False
    type: bool
    description:
    - Indicate caching the volume is enabled.
  change_name:
    required: False
    type: str
    description:
    - Change name of the existing source volume.
  clone:
    required: False
    type: bool
    description:
    - Whether this volume is a clone. Use this attribute in combination with name and snapshot to create a clone by setting clone = true.
  dedupe:
    required: False
    type: bool
    description:
    - Indicate whether dedupe is enabled.
  description:
    required: False
    type: str
    default: null
    description:
    - Text description of volume.
  destination:
    required: False
    type: str
    description:
    - Name of the destination pool where the volume is moving to.
  encryption_cipher:
    required: False
    choices:
    - none
    - aes_256_xts
    type: str
    description:
    - The encryption cipher of the volume.
  folder:
    required: False
    type: str
    description:
    - Name of the folder holding this volume.
  force:
    required: False
    type: bool
    description:
    - Forcibly offline, reduce size or change read-only status a volume.
  force_vvol:
    required: False
    type: bool
    default: False
    description:
    - Forcibly move a virtual volume.
  iscsi_target_scope:
    required: False
    type: str
    choices:
    - volume
    - group
    description:
    - This indicates whether volume is exported under iSCSI Group Target or iSCSI volume target. This attribute is only meaningful to iSCSI system.
  limit:
    required: False
    type: int
    description:
    - Limit on the volume's mapped usage, expressed as a percentage of the volume's size.
  limit_iops:
    required: False
    type: int
    description:
    - IOPS limit for this volume.
  limit_mbps:
    required: False
    type: int
    description:
    - Throughput limit for this volume in MB/s.
  metadata:
    required: False
    type: dict
    description:
    - User defined key-value pairs that augment an volume's attributes. List of key-value pairs. Keys must be unique and non-empty.
      When creating an object, values must be non-empty. When updating an object, an empty value causes the corresponding key to be removed.
  move:
    required: False
    type: bool
    description:
    - Move a volume to different pool.
  multi_initiator:
    required: False
    type: bool
    description:
    - For iSCSI volume target, this flag indicates whether the volume and its snapshots can be accessed from multiple initiators at the same time.
  name:
    required: True
    type: str
    description:
    - Name of the source volume.
  online:
    required: False
    type: bool
    description:
    - Online state of volume, available for host initiators to establish connections.
  owned_by_group:
    required: False
    type: str
    description:
    - Name of group that currently owns the volume.
  parent:
    required: False
    type: str
    description:
    - Name of parent volume.
  perf_policy:
    required: False
    type: str
    default: null
    description:
    - Name of the performance policy. After creating a volume, performance policy for the volume can only be
      changed to another performance policy with same block size.
  pool:
    required: False
    type: str
    description:
    - Name associated with the pool in the storage pool table.
  read_only:
    required: False
    type: bool
    description:
    - Volume is read-only.
  size:
    type: int
    description:
    - Volume size in megabytes. Size is required for creating a volume but not for cloning an existing volume.
  snapshot:
    required: False
    type: str
    description:
    - Base snapshot name. This attribute is required together with name and clone when cloning a volume with the create operation.
  state:
    description:
    - The volume operations.
    choices:
    - present
    - absent
    - create
    - restore
    required: True
    type: str
  thinly_provisioned:
    required: False
    type: bool
    description:
    - Set volume's provisioning level to thin.
  volcoll:
    required: False
    type: str
    description:
    - Name of volume collection of which this volume is a member. Use this attribute in update operation to associate or dissociate volumes with or from
      volume collections. When associating, set this attribute to the name of the volume collection. When dissociating, set this attribute to empty string.
extends_documentation_fragment: hpe.nimble.hpe_nimble
short_description: Manage the HPE Nimble Storage volumes
version_added: "1.0.0"
notes:
  - This module does not support C(check_mode).
'''

EXAMPLES = r'''

# If state is "create", then create a volume if not present. Fails if already present.
# if state is present, then create a volume if not present. Succeeds if it already exists.
- name: Create volume if not present
  hpe.nimble.hpe_nimble_volume:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    state: "{{ state | default('present') }}"
    size: "{{ size }}"
    limit_iops: "{{ limit_iops }}"
    limit_mbps: 5000
    force: false
    metadata: "{{ metadata }}" # metadata = {'mykey1': 'myval1', 'mykey2': 'myval2'}
    description: "{{ description }}"
    name: "{{ name }}"

- name: Changing volume "{{ name }}" to offline state
  hpe.nimble.hpe_nimble_volume:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    online: False
    state: present
    name: "{{ name }}"

- name: Changing volume "{{ name }}" to online state
  hpe.nimble.hpe_nimble_volume:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    online: True
    state: present
    name: "{{ name }}"

# Create a clone from the given snapshot name.
# If snapshot name is not provided then a snapshot is created on the source volume.
# Clone task only run if "parent" is specified. Snapshot is optional.
- name: Create or Refresh a clone
  hpe.nimble.hpe_nimble_volume:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "{{ name }}" # name here is the name of cloned volume
    parent: "{{ parent | mandatory }}"
    snapshot: "{{ snapshot | default(None)}}"
    state: "{{ state | default('present') }}"
  when:
    - parent is defined

- name: Destroy volume (must be offline)
  hpe.nimble.hpe_nimble_volume:
    name: "{{ name }}"
    state: absent

# If no snapshot is given, then restore volume to last snapshot. Fails if no snapshots exist.
# If snapshot is provided, then restore volume from specified snapshot.
- name: Restore volume "{{ name }}"
  hpe.nimble.hpe_nimble_volume:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "{{ name }}"
    snapshot: "{{ snapshot | default(None)}}"
    state: restore

- name: Delete volume "{{ name }}" (must be offline)
  hpe.nimble.hpe_nimble_volume:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "{{ name }}"
    state: absent

- name: Move volume to pool
  hpe.nimble.hpe_nimble_volume:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    move: true
    name: "{{ name }}"
    state: present
    destination: "{{ destination | mandatory }}"

'''
RETURN = r'''
'''

from ansible.module_utils.basic import AnsibleModule
try:
    from nimbleclient.v1 import client
    from nimbleclient import exceptions
except ImportError:
    client = None
from ansible_collections.hpe.nimble.plugins.module_utils.hpe_nimble import __version__ as NIMBLE_ANSIBLE_VERSION
# from hpe_nimble import __version__ as NIMBLE_ANSIBLE_VERSION
import ansible_collections.hpe.nimble.plugins.module_utils.hpe_nimble as utils
from enum import Enum


class Vol_Operation(Enum):
    SUCCESS = 0
    ALREADY_EXISTS = -1
    FAILED = 1

# util functions


def move_volume(
        client_obj,
        vol_name,
        dest_pool,
        force_vvol):

    if utils.is_null_or_empty(vol_name):
        return (False, False, "Volume move failed as volume name is null.", {}, {})

    if utils.is_null_or_empty(dest_pool):
        return (False, False, "Volume move failed as destination pool is null.", {}, {})
    try:
        vol_resp = client_obj.volumes.get(id=None, name=vol_name)
        if utils.is_null_or_empty(vol_resp):
            return (False, False, f"Volume '{vol_name}' not present to move.", {}, {})

        resp = client_obj.volumes.move(id=vol_resp.attrs.get("id"), dest_pool_id=utils.get_pool_id(client_obj, dest_pool), force_vvol=force_vvol)
        return (True, True, f"Volume '{vol_resp.attrs.get('name')}' moved successfully.", {}, resp)
    except Exception as ex:
        return (False, False, f"Volume move failed | '{ex}'", {}, {})


def update_volume(
        client_obj,
        vol_resp,
        **kwargs):

    if utils.is_null_or_empty(vol_resp):
        return (False, False, "Invalid volume to update.", {}, {})
    try:
        changed_attrs_dict, params = utils.remove_unchanged_or_null_args(vol_resp, **kwargs)

        if 'volcoll_name' in kwargs:
            if kwargs['volcoll_name'] == "" and vol_resp.attrs.get('volcoll_id') != "":
                params['volcoll_id'] = ""
                changed_attrs_dict['volcoll_id'] = ""
            else:
                if 'volcoll_name' in params:
                    params.pop('volcoll_name')
                    changed_attrs_dict.pop('volcoll_name')

        if changed_attrs_dict.__len__() > 0:
            resp = client_obj.volumes.update(id=vol_resp.attrs.get("id"), **params)
            return (True, True, f"Volume '{vol_resp.attrs.get('name')}' already present. Modified the following attributes '{changed_attrs_dict}'",
                    changed_attrs_dict, resp.attrs)
        else:
            return (True, False, f"Volume '{vol_resp.attrs.get('name')}' already present in given state.", {}, vol_resp.attrs)
    except Exception as ex:
        return (False, False, f"Volume update failed '{ex}'", {}, {})


def create_volume(
        client_obj,
        vol_name,
        **kwargs):

    if utils.is_null_or_empty(vol_name):
        return (False, False, "Volume creation failed as volume name is null.", {}, {})

    try:
        vol_resp = client_obj.volumes.get(id=None, name=vol_name)
        # remove unchanged and null arguments from kwargs
        params = utils.remove_null_args(**kwargs)
        if utils.is_null_or_empty(vol_resp):
            resp = client_obj.volumes.create(vol_name, **params)
            return (True, True, f"Created volume '{vol_name}' successfully.", {}, resp.attrs)
        else:
            return (False, False, f"Volume '{vol_name}' cannot be created as it is already present in given state.", {}, {})
    except Exception as ex:
        return (False, False, f"Volume creation failed '{ex}'", {}, {})


def delete_volume(client_obj, vol_name):
    if utils.is_null_or_empty(vol_name):
        return (False, False, "Volume deletion failed as volume name is null.", {})

    try:
        vol_resp = client_obj.volumes.get(id=None, name=vol_name)
        if utils.is_null_or_empty(vol_resp):
            return (False, False, f"Volume '{vol_name}' not present to delete.", {})
        else:
            client_obj.volumes.delete(id=vol_resp.attrs.get("id"))
            return (True, True, f"Deleted volume '{vol_name}' successfully.", {})
    except Exception as ex:
        return (False, False, f"Volume deletion for {vol_name} failed '{ex}'", {})


def restore_volume(client_obj, vol_name, snapshot_to_restore=None):
    if utils.is_null_or_empty(vol_name):
        return (False, False, "Volume restore failed as volume name is null.", {}, {})
    try:
        vol_resp = client_obj.volumes.get(id=None, name=vol_name)
        if utils.is_null_or_empty(vol_resp):
            return (False, False, f"Volume '{vol_name}' not present to restore.", {}, {})

        if utils.is_null_or_empty(snapshot_to_restore):
            # restore the volume to the last snapshot
            snap_list_resp = client_obj.snapshots.list(vol_name=vol_name)
            if utils.is_null_or_empty(snap_list_resp):
                return (False, False, f"Volume '{vol_name}' cannot be restored as no snapshot is present in source volume.", {}, {})
            snap_resp = snap_list_resp[-1]
            snapshot_to_restore = snap_resp.attrs.get("name")
        else:
            # get the snapshot detail from the given source vol
            snap_resp = client_obj.snapshots.get(vol_name=vol_name, name=snapshot_to_restore)
            if utils.is_null_or_empty(snap_resp):
                return (False, False, f"Volume '{vol_name}' cannot not be restored as given snapshot name '{snapshot_to_restore}' is not present in"
                        "source volume.", {}, {})

        # offline and restore
        client_obj.volumes.offline(id=vol_resp.attrs.get("id"))
        resp = client_obj.volumes.restore(base_snap_id=snap_resp.attrs.get("id"),
                                          id=vol_resp.attrs.get("id"))
        # bring volume online
        client_obj.volumes.online(id=vol_resp.attrs.get("id"))
        return (True, True, f"Restored volume '{vol_name}' from snapshot '{snapshot_to_restore}' successfully.", {}, resp)
    except Exception as ex:
        return (False, False, f"Volume restore failed '{ex}'", {}, {})


# given a snapshot name,create a clone.
# return code
# SUCCESS = 0
# ALREADY_EXISTS = -1
# FAILED = 1
def create_clone_from_snapshot(
        client_obj,
        snap_list_resp,
        vol_name,
        snapshot_to_clone,
        state):
    # if client_obj is None or not snap_list_resp or snap_list_resp is None or parent is None:
    if (utils.is_null_or_empty(client_obj)
        or utils.is_null_or_empty(vol_name)
            or utils.is_null_or_empty(snap_list_resp)
            or utils.is_null_or_empty(snapshot_to_clone)):
        return (False, "Create clone from snapshot failed as valid arguments are not provided. Please check the argument provided for volume and snapshot.", {})
    try:
        # to_return = Vol_Operation.FAILED  # assume failed
        # find the snapshot from snapshot list
        for snap_obj in snap_list_resp:
            if snap_obj.attrs.get("name") == snapshot_to_clone:
                # create
                resp = client_obj.volumes.create(name=vol_name,
                                                 base_snap_id=snap_obj.attrs.get("id"),
                                                 clone=True)
                if utils.is_null_or_empty(resp) is False:
                    return (Vol_Operation.SUCCESS, f'{vol_name}', resp.attrs)
        return (Vol_Operation.FAILED)
    except exceptions.NimOSAPIError as ex:
        if "SM_eexist" in str(ex):
            # check the state. if it set to present then return true
            if state == "present":
                return (Vol_Operation.ALREADY_EXISTS, f"Cloned volume '{vol_name}' is already present in given state.", {})
            else:
                return (Vol_Operation.FAILED, f"Create clone from snapshot failed as cloned volume '{vol_name}' already exist| {ex}", {})
    except Exception as ex:
        return (Vol_Operation.FAILED, f"Create clone from snapshot failed | {ex}", {})


def clone_volume(
        client_obj,
        parent,
        state,
        vol_name=None,
        snapshot_to_clone=None):

    if utils.is_null_or_empty(vol_name):
        return (False, False, "Clone operation failed. Clone volume name is not present.", {}, {})
    # this function will handle 2 scenario.
    # If snapshot name is given. we try to clone from that else
    # we first create a snapshot of source volume and then
    # clone from the snapshot
    try:
        if utils.is_null_or_empty(snapshot_to_clone):
            if utils.is_null_or_empty(parent):
                return (False, False, "Clone operation failed. Parent volume name is not present.", {}, {})
            # get the vol id
            vol_resp = client_obj.volumes.get(name=parent)
            if utils.is_null_or_empty(vol_resp):
                return (False, False, "Clone operation failed. Parent volume name is not present.", {}, {})
            else:
                # create a temp snapshot
                snapshot_to_clone = utils.get_unique_string("ansible-snapshot")
                snap_resp = client_obj.snapshots.create(name=snapshot_to_clone,
                                                        vol_id=vol_resp.attrs.get("id"),
                                                        description="created by ansible",
                                                        online=False,
                                                        writable=False)
                if utils.is_null_or_empty(snap_resp):
                    return (False, False, "Clone Operation Failed as could not create a snapshot from source volume", {}, {})
                # create clone
                clonevol_resp, msg, resp = create_clone_from_snapshot(client_obj, [snap_resp], vol_name, snapshot_to_clone, state)
                if clonevol_resp == Vol_Operation.ALREADY_EXISTS or clonevol_resp == Vol_Operation.FAILED:
                    # remove the snapshot
                    client_obj.snapshots.delete(id=snap_resp.attrs.get("id"))
        else:
            # get the snapshot detail from the given source vol
            snap_list_resp = client_obj.snapshots.list(vol_name=parent, name=snapshot_to_clone)
            if utils.is_null_or_empty(snap_list_resp):
                return (False, False, f"Could not create clone volume '{vol_name}' as given snapshot name '{snapshot_to_clone}' is not present "
                        "in parent volume", {}, {})
            # create clone
            clonevol_resp, msg, resp = create_clone_from_snapshot(client_obj, snap_list_resp, vol_name, snapshot_to_clone, state)

        if clonevol_resp is Vol_Operation.SUCCESS:
            return (True, True, f"Successfully created cloned volume '{msg}'", {}, resp)
        elif clonevol_resp is Vol_Operation.FAILED:
            return (False, False, f"Failed to clone volume. Msg: '{msg}'", {}, {})
        elif clonevol_resp == Vol_Operation.ALREADY_EXISTS:
            return (True, False, f" '{msg}'", {}, {})
    except Exception as ex:
        return (False, False, f"clone volume operation Failed '{ex}'", {}, {})


def main():

    fields = {
        "state": {
            "required": True,
            "choices": ['present',
                        'absent',
                        'create',
                        'restore'
                        ],
            "type": "str"
        },
        "name": {
            "required": True,
            "type": "str"
        },
        "change_name": {
            "required": False,
            "type": "str"
        },
        "size": {
            "type": "int"
        },
        "description": {
            "required": False,
            "type": "str"
        },
        "perf_policy": {
            "required": False,
            "type": "str"
        },
        "limit": {
            "required": False,
            "type": "int",
        },
        "online": {
            "required": False,
            "type": "bool"
        },
        "owned_by_group": {
            "required": False,
            "type": "str"
        },
        "multi_initiator": {
            "required": False,
            "type": "bool"
        },
        "iscsi_target_scope": {
            "required": False,
            "choices": ['volume', 'group'],
            "type": "str"
        },
        "pool": {
            "required": False,
            "type": "str"
        },
        "read_only": {
            "required": False,
            "type": "bool"
        },
        "block_size": {
            "required": False,
            "type": "int"
        },
        "clone": {
            "required": False,
            "type": "bool"
        },
        "agent_type": {
            "required": False,
            "choices": ['none', 'smis', 'vvol', 'openstack', 'openstackv2'],
            "type": "str"
        },
        "destination": {
            "required": False,
            "type": "str"
        },
        "cache_pinned": {
            "required": False,
            "type": "bool"
        },
        "thinly_provisioned": {
            "required": False,
            "type": "bool"
        },
        "encryption_cipher": {
            "required": False,
            "choices": ['none', 'aes_256_xts'],
            "type": "str"
        },
        "app_uuid": {
            "required": False,
            "type": "str"
        },
        "folder": {
            "required": False,
            "type": "str",
        },
        "dedupe": {
            "required": False,
            "type": "bool"
        },
        "limit_iops": {
            "required": False,
            "type": "int"
        },
        "limit_mbps": {
            "required": False,
            "type": "int"
        },
        "parent": {
            "required": False,
            "type": "str"
        },
        "snapshot": {
            "required": False,
            "type": "str"
        },
        "volcoll": {
            "required": False,
            "type": "str"
        },
        "metadata": {
            "required": False,
            "type": "dict"
        },
        "force": {
            "required": False,
            "type": "bool"
        },
        "caching": {
            "required": False,
            "type": "bool"
        },
        "force_vvol": {
            "required": False,
            "type": "bool",
            "default": False
        },
        "move": {
            "required": False,
            "type": "bool"
        }
    }
    default_fields = utils.basic_auth_arg_fields()
    fields.update(default_fields)
    required_if = [('state', 'restore', ['snapshot'])]

    module = AnsibleModule(argument_spec=fields, required_if=required_if)
    if client is None:
        module.fail_json(msg='Python nimble-sdk could not be found.')

    state = module.params["state"]
    vol_name = module.params["name"]
    change_name = module.params["change_name"]
    size = module.params["size"]
    description = module.params["description"]
    perf_policy = module.params["perf_policy"]
    limit = module.params["limit"]
    online = module.params["online"]
    owned_by_group = module.params["owned_by_group"]
    multi_initiator = module.params["multi_initiator"]
    iscsi_target_scope = module.params["iscsi_target_scope"]
    pool = module.params["pool"]
    read_only = module.params["read_only"]
    block_size = module.params["block_size"]
    clone = module.params["clone"]
    agent_type = module.params["agent_type"]
    dest_pool = module.params["destination"]
    cache_pinned = module.params["cache_pinned"]
    thinly_provisioned = module.params["thinly_provisioned"]
    encryption_cipher = module.params["encryption_cipher"]
    app_uuid = module.params["app_uuid"]
    folder = module.params["folder"]
    dedupe = module.params["dedupe"]
    limit_iops = module.params["limit_iops"]
    limit_mbps = module.params["limit_mbps"]
    parent = module.params["parent"]  # used for cloning
    snapshot = module.params["snapshot"]
    volcoll = module.params["volcoll"]
    metadata = module.params["metadata"]
    force = module.params["force"]
    caching = module.params["caching"]
    force_vvol = module.params["force_vvol"]
    move = module.params["move"]
    hostname = module.params["host"]
    username = module.params["username"]
    password = module.params["password"]

    if (username is None or password is None or hostname is None):
        module.fail_json(msg="Missing variables: hostname, username and password is mandatory.")
    # defaults
    return_status = changed = False
    msg = "No task to run."
    resp = None

    try:
        client_obj = client.NimOSClient(
            hostname,
            username,
            password,
            f"HPE Nimble Ansible Modules v{NIMBLE_ANSIBLE_VERSION}"
        )
        # States
        if move is True and state == "present":
            if utils.is_null_or_empty(dest_pool) is False:
                return_status, changed, msg, changed_attrs_dict, resp = move_volume(client_obj, vol_name, dest_pool, force_vvol)
            else:
                module.fail_json(msg="Volume move failed as destination pool is null.")

        elif (move is None or move is False) and (state == "create" or state == "present"):
            if utils.is_null_or_empty(vol_name):
                return_status = changed = False
                msg = "Volume creation failed as volume name is null"

            # state create/present can be provided for creating a new volume or
            # creating a clone from source volume
            if parent is not None:
                return_status, changed, msg, changed_attrs_dict, resp = clone_volume(
                    client_obj, parent, state,
                    vol_name, snapshot)
            else:
                vol_resp = client_obj.volumes.get(id=None, name=vol_name)
                if utils.is_null_or_empty(vol_resp) or state == "create":
                    return_status, changed, msg, changed_attrs_dict, resp = create_volume(
                        client_obj, vol_name,
                        perfpolicy_id=utils.get_perfpolicy_id(client_obj, perf_policy),
                        size=size,
                        description=description,
                        limit=limit,
                        online=online,
                        owned_by_group_id=utils.get_owned_by_group_id(client_obj, owned_by_group),
                        multi_initiator=multi_initiator,
                        iscsi_target_scope=iscsi_target_scope,
                        pool_id=utils.get_pool_id(client_obj, pool),
                        read_only=read_only,
                        block_size=block_size,
                        clone=clone,
                        agent_type=agent_type,
                        dest_pool_id=utils.get_pool_id(client_obj, dest_pool),
                        cache_pinned=cache_pinned,
                        thinly_provisioned=thinly_provisioned,
                        encryption_cipher=encryption_cipher,
                        app_uuid=app_uuid,
                        folder_id=utils.get_folder_id(client_obj, folder),
                        metadata=metadata,
                        dedupe_enabled=dedupe,
                        limit_iops=limit_iops,
                        limit_mbps=limit_mbps)
                else:
                    return_status, changed, msg, changed_attrs_dict, resp = update_volume(
                        client_obj,
                        vol_resp,
                        name=change_name,
                        volcoll_name=volcoll,
                        size=size,
                        description=description,
                        perfpolicy_id=utils.get_perfpolicy_id(client_obj, perf_policy),
                        limit=limit,
                        online=online,
                        owned_by_group_id=utils.get_owned_by_group_id(client_obj, owned_by_group),
                        multi_initiator=multi_initiator,
                        iscsi_target_scope=iscsi_target_scope,
                        read_only=read_only,
                        block_size=block_size,
                        volcoll_id=utils.get_volcoll_id(client_obj, volcoll),
                        agent_type=agent_type,
                        force=force,
                        cache_pinned=cache_pinned,
                        thinly_provisioned=thinly_provisioned,
                        app_uuid=app_uuid,
                        folder_id=utils.get_folder_id(client_obj, folder),
                        metadata=metadata,
                        caching_enabled=caching,
                        dedupe_enabled=dedupe,
                        limit_iops=limit_iops,
                        limit_mbps=limit_mbps)

        elif state == "absent":
            return_status, changed, msg, changed_attrs_dict = delete_volume(client_obj, vol_name)

        elif state == "restore":
            return_status, changed, msg, changed_attrs_dict, resp = restore_volume(client_obj, vol_name, snapshot)
    except Exception as ex:
        # failed for some reason.
        msg = str(ex)

    if return_status:
        if utils.is_null_or_empty(resp):
            module.exit_json(return_status=return_status, changed=changed, msg=msg)
        else:
            module.exit_json(return_status=return_status, changed=changed, msg=msg, attrs=resp)
    else:
        module.fail_json(return_status=return_status, changed=changed, msg=msg)


if __name__ == '__main__':
    main()

#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2018, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: purefa_hg
version_added: '1.0.0'
short_description: Manage hostgroups on Pure Storage FlashArrays
description:
- Create, delete or modifiy hostgroups on Pure Storage FlashArrays.
author:
- Pure Storage ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - The name of the hostgroup.
    type: str
    required: true
    aliases: [ hostgroup ]
  state:
    description:
    - Define whether the hostgroup should exist or not.
    type: str
    default: present
    choices: [ absent, present ]
  host:
    type: list
    elements: str
    description:
    - List of existing hosts to add to hostgroup.
    - Note that hostnames are case-sensitive however FlashArray hostnames are unique
      and ignore case - you cannot have I(hosta) and I(hostA)
  volume:
    type: list
    elements: str
    description:
    - List of existing volumes to add to hostgroup.
    - Note that volumes are case-sensitive however FlashArray volume names are unique
      and ignore case - you cannot have I(volumea) and I(volumeA)
  lun:
    description:
    - LUN ID to assign to volume for hostgroup. Must be unique.
    - Only applicable when only one volume is specified for connection.
    - If not provided the ID will be automatically assigned.
    - Range for LUN ID is 1 to 4095.
    type: int
  rename:
    description:
    - New name of hostgroup
    type: str
    version_added: '1.10.0'
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Create empty hostgroup
  purestorage.flasharray.purefa_hg:
    name: foo
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Add hosts and volumes to existing or new hostgroup
  purestorage.flasharray.purefa_hg:
    name: foo
    host:
      - host1
      - host2
    volume:
      - vol1
      - vol2
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Delete hosts and volumes from hostgroup
  purestorage.flasharray.purefa_hg:
    name: foo
    host:
      - host1
      - host2
    volume:
      - vol1
      - vol2
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: absent

# This will disconnect all hosts and volumes in the hostgroup
- name: Delete hostgroup
  purestorage.flasharray.purefa_hg:
    name: foo
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: absent

- name: Rename hostgroup
  purestorage.flasharray.purefa_hg:
    name: foo
    rename: bar
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Create host group with hosts and volumes
  purestorage.flasharray.purefa_hg:
    name: bar
    host:
      - host1
      - host2
    volume:
      - vol1
      - vol2
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_system,
    purefa_argument_spec,
)


def rename_exists(module, array):
    """Determine if rename target already exists"""
    exists = False
    new_name = module.params["rename"]
    for hgroup in array.list_hgroups():
        if hgroup["name"].casefold() == new_name.casefold():
            exists = True
            break
    return exists


def get_hostgroup(module, array):
    hostgroup = None

    for host in array.list_hgroups():
        if host["name"].casefold() == module.params["name"].casefold():
            hostgroup = host
            break

    return hostgroup


def make_hostgroup(module, array):
    if module.params["rename"]:
        module.fail_json(
            msg="Hostgroup {0} does not exist - rename failed.".format(
                module.params["name"]
            )
        )
    changed = True
    if not module.check_mode:
        try:
            array.create_hgroup(module.params["name"])
        except Exception:
            module.fail_json(
                msg="Failed to create hostgroup {0}".format(module.params["name"])
            )
        if module.params["host"]:
            array.set_hgroup(module.params["name"], hostlist=module.params["host"])
        if module.params["volume"]:
            if len(module.params["volume"]) == 1 and module.params["lun"]:
                try:
                    array.connect_hgroup(
                        module.params["name"],
                        module.params["volume"][0],
                        lun=module.params["lun"],
                    )
                except Exception:
                    module.fail_json(
                        msg="Failed to add volume {0} with LUN ID {1}".format(
                            module.params["volume"][0], module.params["lun"]
                        )
                    )
            else:
                for vol in module.params["volume"]:
                    try:
                        array.connect_hgroup(module.params["name"], vol)
                    except Exception:
                        module.fail_json(msg="Failed to add volume to hostgroup")
    module.exit_json(changed=changed)


def update_hostgroup(module, array):
    changed = False
    renamed = False
    hgroup = get_hostgroup(module, array)
    current_hostgroup = module.params["name"]
    volumes = array.list_hgroup_connections(module.params["name"])
    if module.params["state"] == "present":
        if module.params["rename"]:
            if not rename_exists(module, array):
                try:
                    if not module.check_mode:
                        array.rename_hgroup(
                            module.params["name"], module.params["rename"]
                        )
                    current_hostgroup = module.params["rename"]
                    renamed = True
                except Exception:
                    module.fail_json(
                        msg="Rename to {0} failed.".format(module.params["rename"])
                    )
            else:
                module.warn(
                    "Rename failed. Hostgroup {0} already exists. Continuing with other changes...".format(
                        module.params["rename"]
                    )
                )
        if module.params["host"]:
            cased_hosts = list(module.params["host"])
            cased_hghosts = list(hgroup["hosts"])
            new_hosts = list(set(cased_hosts).difference(cased_hghosts))
            if new_hosts:
                try:
                    if not module.check_mode:
                        array.set_hgroup(current_hostgroup, addhostlist=new_hosts)
                    changed = True
                except Exception:
                    module.fail_json(msg="Failed to add host(s) to hostgroup")
        if module.params["volume"]:
            if volumes:
                current_vols = [vol["vol"] for vol in volumes]
                cased_vols = list(module.params["volume"])
                new_volumes = list(set(cased_vols).difference(set(current_vols)))
                if len(new_volumes) == 1 and module.params["lun"]:
                    try:
                        if not module.check_mode:
                            array.connect_hgroup(
                                current_hostgroup,
                                new_volumes[0],
                                lun=module.params["lun"],
                            )
                        changed = True
                    except Exception:
                        module.fail_json(
                            msg="Failed to add volume {0} with LUN ID {1}".format(
                                new_volumes[0], module.params["lun"]
                            )
                        )
                else:
                    for cvol in new_volumes:
                        try:
                            if not module.check_mode:
                                array.connect_hgroup(current_hostgroup, cvol)
                            changed = True
                        except Exception:
                            module.fail_json(
                                msg="Failed to connect volume {0} to hostgroup {1}.".format(
                                    cvol, current_hostgroup
                                )
                            )
            else:
                if len(module.params["volume"]) == 1 and module.params["lun"]:
                    try:
                        if not module.check_mode:
                            array.connect_hgroup(
                                current_hostgroup,
                                module.params["volume"][0],
                                lun=module.params["lun"],
                            )
                        changed = True
                    except Exception:
                        module.fail_json(
                            msg="Failed to add volume {0} with LUN ID {1}".format(
                                module.params["volume"], module.params["lun"]
                            )
                        )
                else:
                    for cvol in module.params["volume"]:
                        try:
                            if not module.check_mode:
                                array.connect_hgroup(current_hostgroup, cvol)
                            changed = True
                        except Exception:
                            module.fail_json(
                                msg="Failed to connect volume {0} to hostgroup {1}.".format(
                                    cvol, current_hostgroup
                                )
                            )
    else:
        if module.params["host"]:
            cased_old_hosts = list(module.params["host"])
            cased_hosts = list(hgroup["hosts"])
            old_hosts = list(set(cased_old_hosts).intersection(cased_hosts))
            if old_hosts:
                try:
                    if not module.check_mode:
                        array.set_hgroup(current_hostgroup, remhostlist=old_hosts)
                    changed = True
                except Exception:
                    module.fail_json(
                        msg="Failed to remove hosts {0} from hostgroup {1}".format(
                            old_hosts, current_hostgroup
                        )
                    )
        if module.params["volume"]:
            cased_old_vols = list(module.params["volume"])
            old_volumes = list(
                set(cased_old_vols).intersection(set([vol["vol"] for vol in volumes]))
            )
            if old_volumes:
                changed = True
                for cvol in old_volumes:
                    try:
                        if not module.check_mode:
                            array.disconnect_hgroup(current_hostgroup, cvol)
                    except Exception:
                        module.fail_json(
                            msg="Failed to disconnect volume {0} from hostgroup {1}".format(
                                cvol, current_hostgroup
                            )
                        )
    changed = changed or renamed
    module.exit_json(changed=changed)


def delete_hostgroup(module, array):
    changed = True
    try:
        vols = array.list_hgroup_connections(module.params["name"])
    except Exception:
        module.fail_json(
            msg="Failed to get volume connection for hostgroup {0}".format(
                module.params["hostgroup"]
            )
        )
    if not module.check_mode:
        for vol in vols:
            try:
                array.disconnect_hgroup(module.params["name"], vol["vol"])
            except Exception:
                module.fail_json(
                    msg="Failed to disconnect volume {0} from hostgroup {1}".format(
                        vol["vol"], module.params["name"]
                    )
                )
        host = array.get_hgroup(module.params["name"])
        if not module.check_mode:
            try:
                array.set_hgroup(module.params["name"], remhostlist=host["hosts"])
                try:
                    array.delete_hgroup(module.params["name"])
                except Exception:
                    module.fail_json(
                        msg="Failed to delete hostgroup {0}".format(
                            module.params["name"]
                        )
                    )
            except Exception:
                module.fail_json(
                    msg="Failed to remove hosts {0} from hostgroup {1}".format(
                        host["hosts"], module.params["name"]
                    )
                )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True, aliases=["hostgroup"]),
            state=dict(type="str", default="present", choices=["absent", "present"]),
            host=dict(type="list", elements="str"),
            lun=dict(type="int"),
            rename=dict(type="str"),
            volume=dict(type="list", elements="str"),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    state = module.params["state"]
    array = get_system(module)
    hostgroup = get_hostgroup(module, array)

    if module.params["host"]:
        try:
            for hst in module.params["host"]:
                array.get_host(hst)
        except Exception:
            module.fail_json(msg="Host {0} not found".format(hst))
    if module.params["lun"] and len(module.params["volume"]) > 1:
        module.fail_json(msg="LUN ID cannot be specified with multiple volumes.")

    if module.params["lun"] and not 1 <= module.params["lun"] <= 4095:
        module.fail_json(
            msg="LUN ID of {0} is out of range (1 to 4095)".format(module.params["lun"])
        )

    if module.params["volume"]:
        try:
            for vol in module.params["volume"]:
                array.get_volume(vol)
        except Exception:
            module.exit_json(changed=False)

    if hostgroup and state == "present":
        update_hostgroup(module, array)
    elif hostgroup and module.params["volume"] and state == "absent":
        update_hostgroup(module, array)
    elif hostgroup and module.params["host"] and state == "absent":
        update_hostgroup(module, array)
    elif hostgroup and state == "absent":
        delete_hostgroup(module, array)
    elif hostgroup is None and state == "absent":
        module.exit_json(changed=False)
    else:
        make_hostgroup(module, array)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

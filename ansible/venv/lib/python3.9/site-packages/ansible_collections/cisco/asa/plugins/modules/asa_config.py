#!/usr/bin/python
#
# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = """
module: asa_config
author: Peter Sprygada (@privateip), Patrick Ogenstad (@ogenstad)
short_description: Manage configuration sections on Cisco ASA devices
description:
- Cisco ASA configurations use a simple block indent file syntax for segmenting configuration
  into sections.  This module provides an implementation for working with ASA configuration
  sections in a deterministic way.
version_added: 1.0.0
extends_documentation_fragment:
- cisco.asa.asa
options:
  lines:
    description:
    - The ordered set of commands that should be configured in the section.  The commands
      must be the exact same commands as found in the device running-config.  Be sure
      to note the configuration command syntax as some commands are automatically
      modified by the device config parser.
    aliases:
    - commands
    type: list
    elements: str
  parents:
    description:
    - The ordered set of parents that uniquely identify the section or hierarchy the
      commands should be checked against.  If the parents argument is omitted, the
      commands are checked against the set of top level or global commands.
    type: list
    elements: str
  src:
    description:
    - Specifies the source path to the file that contains the configuration or configuration
      template to load.  The path to the source file can either be the full path on
      the Ansible control host or a relative path from the playbook or role root directory.  This
      argument is mutually exclusive with I(lines), I(parents).
    type: path
  before:
    description:
    - The ordered set of commands to push on to the command stack if a change needs
      to be made.  This allows the playbook designer the opportunity to perform configuration
      commands prior to pushing any changes without affecting how the set of commands
      are matched against the system.
    type: list
    elements: str
  after:
    description:
    - The ordered set of commands to append to the end of the command stack if a change
      needs to be made.  Just like with I(before) this allows the playbook designer
      to append a set of commands to be executed after the command set.
    type: list
    elements: str
  match:
    description:
    - Instructs the module on the way to perform the matching of the set of commands
      against the current device config.  If match is set to I(line), commands are
      matched line by line.  If match is set to I(strict), command lines are matched
      with respect to position.  If match is set to I(exact), command lines must be
      an equal match.  Finally, if match is set to I(none), the module will not attempt
      to compare the source configuration with the running configuration on the remote
      device.
    default: line
    choices:
    - line
    - strict
    - exact
    - none
    type: str
  replace:
    description:
    - Instructs the module on the way to perform the configuration on the device.  If
      the replace argument is set to I(line) then the modified lines are pushed to
      the device in configuration mode.  If the replace argument is set to I(block)
      then the entire command block is pushed to the device in configuration mode
      if any line is not correct
    default: line
    choices:
    - line
    - block
    type: str
  backup:
    description:
    - This argument will cause the module to create a full backup of the current C(running-config)
      from the remote device before any changes are made. If the C(backup_options)
      value is not given, the backup file is written to the C(backup) folder in the
      playbook root directory. If the directory does not exist, it is created.
    type: bool
    default: no
  config:
    description:
    - The C(config) argument allows the playbook designer to supply the base configuration
      to be used to validate configuration changes necessary.  If this argument is
      provided, the module will not download the running-config from the remote node.
    type: str
  defaults:
    description:
    - This argument specifies whether or not to collect all defaults when getting
      the remote device running config.  When enabled, the module will get the current
      config by issuing the command C(show running-config all).
    type: bool
    default: no
  passwords:
    description:
    - This argument specifies to include passwords in the config when retrieving the
      running-config from the remote device.  This includes passwords related to VPN
      endpoints.  This argument is mutually exclusive with I(defaults).
    type: bool
  save:
    description:
    - The C(save) argument instructs the module to save the running- config to the
      startup-config at the conclusion of the module running.  If check mode is specified,
      this argument is ignored.
    type: bool
    default: no
  backup_options:
    description:
    - This is a dict object containing configurable options related to backup file
      path. The value of this option is read only when C(backup) is set to I(yes),
      if C(backup) is set to I(no) this option will be silently ignored.
    suboptions:
      filename:
        description:
        - The filename to be used to store the backup configuration. If the filename
          is not given it will be generated based on the hostname, current time and
          date in format defined by <hostname>_config.<current-date>@<current-time>
        type: str
      dir_path:
        description:
        - This option provides the path ending with directory name in which the backup
          configuration file will be stored. If the directory does not exist it will
          be first created and the filename is either the value of C(filename) or
          default filename as described in C(filename) options description. If the
          path value is not given in that case a I(backup) directory will be created
          in the current working directory and backup configuration will be copied
          in C(filename) within I(backup) directory.
        type: path
    type: dict
  save_when:
    description:
    - When changes are made to the device running-configuration, the changes are not
      copied to non-volatile storage by default.  Using this argument will change
      that before.  If the argument is set to I(always), then the running-config will
      always be copied to the startup-config and the I(modified) flag will always
      be set to True.  If the argument is set to I(modified), then the running-config
      will only be copied to the startup-config if it has changed since the last save
      to startup-config.  If the argument is set to I(never), the running-config will
      never be copied to the startup-config.  If the argument is set to I(changed),
      then the running-config will only be copied to the startup-config if the task
      has made a change. I(changed) was added in Ansible 2.5.
    default: never
    version_added: 1.1.0
    choices:
    - always
    - never
    - modified
    - changed
    type: str
"""

EXAMPLES = """
- cisco.asa.asa_config:
    lines:
    - network-object host 10.80.30.18
    - network-object host 10.80.30.19
    - network-object host 10.80.30.20
    parents: [object-group network OG-MONITORED-SERVERS]

- cisco.asa.asa_config:
    host: '{{ inventory_hostname }}'
    lines:
    - message-length maximum client auto
    - message-length maximum 512
    match: line
    parents: [policy-map type inspect dns PM-DNS, parameters]
    authorize: yes
    auth_pass: cisco
    username: admin
    password: cisco
    context: ansible

- cisco.asa.asa_config:
    lines:
    - ikev1 pre-shared-key MyS3cretVPNK3y
    parents: tunnel-group 1.1.1.1 ipsec-attributes
    passwords: yes

- name: attach ASA acl on interface vlan13/nameif cloud13
  cisco.asa.asa_config:
    lines:
    - access-group cloud-acl_access_in in interface cloud13

- name: configure ASA (>=9.2) default BGP
  cisco.asa.asa_config:
    lines:
    - bgp log-neighbor-changes
    - bgp bestpath compare-routerid
    parents:
    - router bgp 65002
  register: bgp
  when: bgp_default_config is defined
- name: configure ASA (>=9.2) BGP neighbor in default/single context mode
  cisco.asa.asa_config:
    lines:
    - bgp router-id {{ bgp_router_id }}
    - neighbor {{ bgp_neighbor_ip }} remote-as {{ bgp_neighbor_as }}
    - neighbor {{ bgp_neighbor_ip }} description {{ bgp_neighbor_name }}
    parents:
    - router bgp 65002
    - address-family ipv4 unicast
  register: bgp
  when: bgp_neighbor_as is defined
- name: configure ASA interface with standby
  cisco.asa.asa_config:
    lines:
    - description my cloud interface
    - nameif cloud13
    - security-level 50
    - ip address 192.168.13.1 255.255.255.0 standby 192.168.13.2
    parents: [interface Vlan13]
  register: interface
- name: Show changes to interface from task above
  ansible.builtin.debug:
    var: interface

- name: configurable backup path
  cisco.asa.asa_config:
    lines:
    - access-group cloud-acl_access_in in interface cloud13
    backup: yes
    backup_options:
      filename: backup.cfg
      dir_path: /home/user

- name: save running to startup when modified
  cisco.asa.asa_config:
    save_when: modified
"""

RETURN = """
updates:
  description: The set of commands that will be pushed to the remote device
  returned: always
  type: list
  sample: ['...', '...']
backup_path:
  description: The full path to the backup file
  returned: when backup is yes
  type: str
  sample: /playbooks/ansible/backup/asa_config.2016-07-16@22:28:34
"""
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.config import (
    NetworkConfig,
    dumps,
)

from ansible_collections.cisco.asa.plugins.module_utils.network.asa.asa import (
    asa_argument_spec,
    check_args,
    get_config,
    load_config,
    run_commands,
)


def get_candidate(module):
    candidate = NetworkConfig(indent=1)
    if module.params["src"]:
        candidate.load(module.params["src"])
    elif module.params["lines"]:
        parents = module.params["parents"] or list()
        candidate.add(module.params["lines"], parents=parents)
    return candidate


def save_config(module, result):
    result["changed"] = True
    if not module.check_mode:
        run_commands(module, "write mem")


def run(module, result):
    match = module.params["match"]
    replace = module.params["replace"]
    path = module.params["parents"]

    candidate = get_candidate(module)
    if match != "none":
        contents = module.params["config"]
        if not contents:
            contents = get_config(module)
        config = NetworkConfig(indent=1, contents=contents)
        configobjs = candidate.difference(
            config,
            path=path,
            match=match,
            replace=replace,
        )

    else:
        configobjs = candidate.items

    if configobjs:
        commands = dumps(configobjs, "commands").split("\n")

        if module.params["lines"]:
            if module.params["before"]:
                commands[:0] = module.params["before"]

            if module.params["after"]:
                commands.extend(module.params["after"])

        result["updates"] = commands

        # send the configuration commands to the device and merge
        # them with the current running config
        if not module.check_mode:
            load_config(module, commands)
        result["changed"] = True

    if module.params["save"]:
        module.warn(
            "module param save is deprecated, please use newer and updated param save_when instead which is released with more functionality!",
        )
        save_config(module, result)
    if module.params["save_when"] == "always":
        save_config(module, result)
    elif module.params["save_when"] == "modified":
        running_config_checksum = run_commands(
            module,
            "show running-config | include checksum:",
        )
        startup_config_checksum = run_commands(
            module,
            "show startup-config | include checksum:",
        )
        if running_config_checksum != startup_config_checksum:
            save_config(module, result)
    elif module.params["save_when"] == "changed" and result["changed"]:
        save_config(module, result)


def main():
    """main entry point for module execution"""
    backup_spec = dict(filename=dict(), dir_path=dict(type="path"))
    argument_spec = dict(
        src=dict(type="path"),
        lines=dict(aliases=["commands"], type="list", elements="str"),
        parents=dict(type="list", elements="str"),
        before=dict(type="list", elements="str"),
        after=dict(type="list", elements="str"),
        match=dict(
            default="line",
            choices=["line", "strict", "exact", "none"],
        ),
        replace=dict(default="line", choices=["line", "block"]),
        backup_options=dict(type="dict", options=backup_spec),
        config=dict(),
        defaults=dict(type="bool", default=False),
        passwords=dict(type="bool", default=False),
        backup=dict(type="bool", default=False),
        save=dict(type="bool", default=False),
        save_when=dict(
            choices=["always", "never", "modified", "changed"],
            default="never",
        ),
    )

    argument_spec.update(asa_argument_spec)

    mutually_exclusive = [
        ("lines", "src"),
        ("parents", "src"),
        ("defaults", "passwords"),
    ]

    required_if = [
        ("match", "strict", ["lines"]),
        ("match", "exact", ["lines"]),
        ("replace", "block", ["lines"]),
    ]

    module = AnsibleModule(
        argument_spec=argument_spec,
        mutually_exclusive=mutually_exclusive,
        required_if=required_if,
        supports_check_mode=True,
    )

    result = {"changed": False}

    check_args(module)

    if module.params["backup"]:
        result["__backup__"] = get_config(module)

    run(module, result)

    module.exit_json(**result)


if __name__ == "__main__":
    main()

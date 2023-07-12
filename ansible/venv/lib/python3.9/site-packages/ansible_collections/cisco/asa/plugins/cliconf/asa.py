#
# (c) 2017 Red Hat Inc.
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#
from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
---
author: Ansible Security Team (@ansible-security)
name: asa
short_description: Use asa cliconf to run command on Cisco ASA platform
description:
- This asa plugin provides low level abstraction apis for sending and receiving CLI
  commands from Cisco ASA network devices.
version_added: 1.0.0
options:
  config_commands:
    description:
    - Specifies a list of commands that can make configuration changes
      to the target device.
    - When `ansible_network_single_user_mode` is enabled, if a command sent
      to the device is present in this list, the existing cache is invalidated.
    version_added: 2.0.0
    type: list
    elements: str
    default: []
    vars:
    - name: ansible_asa_config_commands
"""

import json
import re

from itertools import chain

from ansible.errors import AnsibleConnectionFailure
from ansible.module_utils._text import to_text
from ansible.module_utils.common._collections_compat import Mapping
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import to_list
from ansible_collections.ansible.netcommon.plugins.plugin_utils.cliconf_base import (
    CliconfBase,
    enable_mode,
)


class Cliconf(CliconfBase):
    def __init__(self, *args, **kwargs):
        super(Cliconf, self).__init__(*args, **kwargs)
        self._device_info = {}

    def get_device_info(self):
        if not self._device_info:
            device_info = {}

            device_info["network_os"] = "asa"
            reply = self.get("show version")
            data = to_text(reply, errors="surrogate_or_strict").strip()

            match = re.search(r"Version (\S+)", data)
            if match:
                device_info["network_os_version"] = match.group(1)

            match = re.search(r"Firepower .+ Version (\S+)", data)
            if match:
                device_info["network_os_firepower_version"] = match.group(1)

            match = re.search(r"Device .+ Version (\S+)", data)
            if match:
                device_info["network_os_device_mgr_version"] = match.group(1)

            match = re.search(r"^Model Id:\s+(.+) \(revision", data, re.M)
            if match:
                device_info["network_os_model"] = match.group(1)

            match = re.search(r"^(.+) up", data, re.M)
            if match:
                device_info["network_os_hostname"] = match.group(1)

            match = re.search(r'image file is "(.+)"', data)
            if match:
                device_info["network_os_image"] = match.group(1)

            self._device_info = device_info

        return self._device_info

    @enable_mode
    def get_config(self, source="running", flags=None, format="text"):
        if source not in ("running", "startup"):
            return self.invalid_params(
                "fetching configuration from %s is not supported" % source,
            )
        if source == "running":
            cmd = "show running-config all"
        else:
            cmd = "show startup-config"
        return self.send_command(cmd)

    @enable_mode
    def edit_config(self, command):
        for cmd in chain(["configure terminal"], to_list(command), ["end"]):
            self.send_command(cmd)

    def get(
        self,
        command,
        prompt=None,
        answer=None,
        sendonly=False,
        newline=True,
        check_all=False,
    ):
        return self.send_command(
            command=command,
            prompt=prompt,
            answer=answer,
            sendonly=sendonly,
            newline=newline,
            check_all=check_all,
        )

    def get_capabilities(self):
        result = super(Cliconf, self).get_capabilities()
        return json.dumps(result)

    def run_commands(self, commands=None, check_rc=True):
        if commands is None:
            raise ValueError("'commands' value is required")

        responses = list()
        for cmd in to_list(commands):
            if not isinstance(cmd, Mapping):
                cmd = {"command": cmd}

            output = cmd.pop("output", None)
            if output:
                raise ValueError(
                    "'output' value %s is not supported for run_commands" % output,
                )

            try:
                out = self.send_command(**cmd)
            except AnsibleConnectionFailure as e:
                if check_rc:
                    raise
                out = getattr(e, "err", to_text(e))

            responses.append(out)

        return responses

# -*- coding: utf-8 -*-
#
# Copyright (c) 2021 T-Systems Multimedia Solutions GmbH
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# This module is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this software.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
name: icinga_director_inventory
short_description: Returns Ansible inventory from Icinga
description: Returns Ansible inventory from Icinga
author:
- Sebastian Gumprich (@rndmh3ro)
options:
    plugin:
        description: Name of the plugin
        required: true
        choices: ['t_systems_mms.icinga_director.icinga_director_inventory']
    url:
        description: Icinga URL to connect to
        required: true
extends_documentation_fragment:
  - ansible.builtin.url
  - constructed
"""

EXAMPLES = r"""
plugin: t_systems_mms.icinga_director.icinga_director_inventory
url: 'https://example.com'
url_username: foo
url_password: bar
force_basic_auth: False
strict: False

# use the object_name you defined as hostname
compose:
  hostname: object_name

# create a group based on the operating system defined in a custom variable
keyed_groups:
  - prefix: os
    key: vars.HostOS

# create groups based on jinja templates
# here we create a group called "rb" if the host variable "check_period" is "24/7"
groups:
  rb: check_period == "24/7"
"""


from ansible.plugins.inventory import BaseInventoryPlugin, Constructable

from ansible.module_utils.urls import open_url
import json


class InventoryModule(BaseInventoryPlugin, Constructable):
    NAME = "t_systems_mms.icinga_director.icinga_director_inventory"

    def call_url(self, url, url_username, url_password, url_path):
        """
        Execute the request against the API with the provided arguments and return json.
        """

        headers = {
            "Accept": "application/json",
            "X-HTTP-Method-Override": "GET",
        }
        url = url + url_path
        rsp = open_url(
            url,
            url_username=self.url_username,
            url_password=self.url_password,
            force_basic_auth=self.force_basic_auth,
            headers=headers,
        )
        content = ""
        if rsp:
            content = json.loads(rsp.read().decode("utf-8"))
            return content

    def verify_file(self, path):
        """Verify the configuration file."""
        if super(InventoryModule, self).verify_file(path):
            endings = (
                "icinga_director_inventory.yaml",
                "icinga_director_inventory.yml",
            )
            if any((path.endswith(ending) for ending in endings)):
                return True
        return False

    def add_hosts_to_groups(self):
        hostgroups = self.set_hostgroups()

        for hostgroup in hostgroups:
            members = self.call_url(
                self.url,
                self.url_username,
                self.url_password,
                url_path="/monitoring/list/hosts"
                + "?hostgroup_name="
                + hostgroup,
            )
            for member in members:
                self.inventory.add_host(member["host_name"], group=hostgroup)

    def set_hostgroups(self):
        hostgroup_list = self.call_url(
            self.url,
            self.url_username,
            self.url_password,
            url_path="/director/hostgroups",
        )

        hostgroups = []

        for hostgroup in hostgroup_list["objects"]:
            hostgroups.append(hostgroup["object_name"])
            self.inventory.add_group(hostgroup["object_name"])
        return hostgroups

    def parse(self, inventory, loader, path, cache=True):
        """Return dynamic inventory from source"""

        # call base method to ensure properties are available for use with other helper methods
        super(InventoryModule, self).parse(inventory, loader, path, cache)

        # Read the inventory YAML file
        self._read_config_data(path)

        # Store the options from the YAML file
        self.plugin = self.get_option("plugin")
        self.url = self.get_option("url")
        self.url_username = self.get_option("url_username")
        self.url_password = self.get_option("url_password")
        self.force_basic_auth = self.get_option("force_basic_auth")
        strict = self.get_option("strict")
        compose = self.get_option("compose")

        host_list = self.call_url(
            self.url,
            self.url_username,
            self.url_password,
            url_path="/director/hosts" + "?resolved",
        )

        for host in host_list["objects"]:
            self.inventory.add_host(host["object_name"], group="all")
            for item in host:
                self.inventory.set_variable(
                    host["object_name"], item, host[item]
                )

            host_vars = self.inventory.get_host(host["object_name"]).get_vars()

            # Add variables created by the user's Jinja2 expressions to the host
            self._set_composite_vars(
                compose,
                host_vars,
                host["object_name"],
                strict=strict,
            )

            # The following two methods combine the provided variables dictionary with the latest host variables
            # Using these methods after _set_composite_vars() allows groups to be created with the composed variables
            self._add_host_to_composed_groups(
                self.get_option("groups"),
                host_vars,
                host["object_name"],
                strict=strict,
            )
            self._add_host_to_keyed_groups(
                self.get_option("keyed_groups"),
                host_vars,
                host["object_name"],
                strict=strict,
            )

        self.add_hosts_to_groups()

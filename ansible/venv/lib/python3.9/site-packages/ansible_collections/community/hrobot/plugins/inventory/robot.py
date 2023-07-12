# -*- coding: utf-8 -*-

# Copyright (c) 2019 Oleksandr Stepanov <alexandrst88@gmail.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later


from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
    name: robot
    author:
        - Oleksandr Stepanov (@alexandrst88)
    short_description: Hetzner Robot inventory source
    version_added: 1.1.0
    description:
        - Reads servers from Hetzner Robot API.
        - Uses a YAML configuration file that ends with C(robot.yml) or C(robot.yaml).
        - The inventory plugin adds all values from U(https://robot.your-server.de/doc/webservice/en.html#get-server)
          prepended with C(hrobot_) to the server's inventory.
          For example, the variable C(hrobot_dc) contains the data center the server is located in.
    extends_documentation_fragment:
        - ansible.builtin.constructed
        - ansible.builtin.inventory_cache
        - community.hrobot.robot
    notes:
        - The I(hetzner_user) and I(hetzner_password) options can be templated.
    options:
        plugin:
            description: Token that ensures this is a source file for the plugin.
            required: true
            choices: ["community.hrobot.robot"]
        hetzner_user:
            env:
                - name: HROBOT_API_USER
        hetzner_password:
            env:
                - name: HROBOT_API_PASSWORD
        filters:
            description:
                - A dictionary of filter value pairs.
                - Available filters are listed here are keys of server like C(status) or C(server_ip).
                - See U(https://robot.your-server.de/doc/webservice/en.html#get-server) for all values that can be used.
            type: dict
            default: {}
"""

EXAMPLES = r"""
# Fetch all hosts in Hetzner Robot
plugin: community.hrobot.robot
# Filters all servers in ready state
filters:
  status: ready

# Example showing encrypted credentials
# (This assumes that Mozilla sops was used to encrypt keys/hetzner.sops.yaml, which contains two values
# hetzner_username and hetzner_password. Needs the community.sops collection to decode that file.)
plugin: community.hrobot.robot
hetzner_user: '{{ (lookup("community.sops.sops", "keys/hetzner.sops.yaml") | from_yaml).hetzner_username }}'
hetzner_password: '{{ (lookup("community.sops.sops", "keys/hetzner.sops.yaml") | from_yaml).hetzner_password }}'

# Example using constructed features to create groups
plugin: community.hrobot.robot
filters:
  status: ready
  traffic: unlimited
# keyed_groups may be used to create custom groups
strict: false
keyed_groups:
  # Add e.g. groups for every data center
  - key: hrobot_dc
    separator: ""
# Use the IP address to connect to the host
compose:
  server_name_ip: hrobot_server_name ~ '-' ~ hrobot_server_ip
"""

from ansible.errors import AnsibleError
from ansible.plugins.inventory import BaseInventoryPlugin, Constructable, Cacheable
from ansible.template import Templar
from ansible.utils.display import Display

from ansible_collections.community.hrobot.plugins.module_utils.robot import (
    BASE_URL,
    PluginException,
    plugin_open_url_json,
)

display = Display()


class InventoryModule(BaseInventoryPlugin, Constructable, Cacheable):

    NAME = 'community.hrobot.robot'

    def verify_file(self, path):
        ''' return true/false if this is possibly a valid file for this plugin to consume '''
        valid = False
        if super(InventoryModule, self).verify_file(path):
            # base class verifies that file exists and is readable by current user
            if path.endswith(('robot.yaml', 'robot.yml')):
                valid = True
            else:
                display.debug("robot inventory filename must end with 'robot.yml' or 'robot.yaml'")
        return valid

    def parse(self, inventory, loader, path, cache=True):
        super(InventoryModule, self).parse(inventory, loader, path)
        servers = {}
        config = self._read_config_data(path)
        self.load_cache_plugin()
        cache_key = self.get_cache_key(path)

        self.templar = Templar(loader=loader)

        # cache may be True or False at this point to indicate if the inventory is being refreshed
        # get the user's cache option too to see if we should save the cache if it is changing
        user_cache_setting = self.get_option('cache')

        # read if the user has caching enabled and the cache isn't being refreshed
        attempt_to_read_cache = user_cache_setting and cache
        # update if the user has caching enabled and the cache is being refreshed; update this value to True if the cache has expired below
        cache_needs_update = user_cache_setting and not cache

        # attempt to read the cache if inventory isn't being refreshed and the user has caching enabled
        if attempt_to_read_cache:
            try:
                servers = self._cache[cache_key]
            except KeyError:
                # This occurs if the cache_key is not in the cache or if the cache_key expired, so the cache needs to be updated
                cache_needs_update = True
        elif not cache_needs_update:
            servers = self.get_servers()

        if cache_needs_update:
            servers = self.get_servers()

            # set the cache
            self._cache[cache_key] = servers

        self.populate(servers)

    def populate(self, servers):
        filters = self.get_option('filters')
        strict = self.get_option('strict')
        server_lists = []
        for server in servers:
            s = server['server']
            server_name = s.get('server_name') or s.get('server_ip') or str(s['server_number'])
            matched = self.filter(s, filters)
            if not matched:
                continue

            if server_name in server_lists:
                display.warning('Two of your Hetzner servers use the same server name ({0}). '
                                'Please make sure that your server names are unique. '
                                'Only the first server named {0} will be included in the inventory.'.format(server_name))
                continue

            self.inventory.add_host(server_name)
            server_lists.append(server_name)
            if 'server_ip' in s:
                self.inventory.set_variable(server_name, 'ansible_host', s['server_ip'])
            for hostvar, hostval in s.items():
                self.inventory.set_variable(server_name, "{0}_{1}".format('hrobot', hostvar), hostval)

            # Composed variables
            server_vars = self.inventory.get_host(server_name).get_vars()
            self._set_composite_vars(self.get_option('compose'), server_vars, server_name, strict=strict)

            # Complex groups based on jinja2 conditionals, hosts that meet the conditional are added to group
            self._add_host_to_composed_groups(self.get_option('groups'), server, server_name, strict=strict)

            # Create groups based on variable values and add the corresponding hosts to it
            self._add_host_to_keyed_groups(self.get_option('keyed_groups'), server, server_name, strict=strict)

    def filter(self, server, filters):
        matched = True
        for key, value in filters.items():
            if server.get(key) != value:
                matched = False
                break
        return matched

    def get_servers(self):
        try:
            return plugin_open_url_json(self, '{0}/server'.format(BASE_URL), templar=self.templar)[0]
        except PluginException as e:
            raise AnsibleError(e.error_message)

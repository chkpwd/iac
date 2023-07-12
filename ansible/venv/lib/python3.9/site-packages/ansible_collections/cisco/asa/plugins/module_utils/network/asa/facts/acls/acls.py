#
# -*- coding: utf-8 -*-
# Copyright 2019 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The asa_acls fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type


from copy import deepcopy

from ansible.module_utils.six import iteritems
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.network_template import (
    NetworkTemplate,
)

from ansible_collections.cisco.asa.plugins.module_utils.network.asa.argspec.acls.acls import (
    AclsArgs,
)
from ansible_collections.cisco.asa.plugins.module_utils.network.asa.rm_templates.acls import (
    AclsTemplate,
)


class AclsFacts(object):
    """The asa_acls fact class"""

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = AclsArgs.argument_spec
        spec = deepcopy(self.argument_spec)
        if subspec:
            if options:
                facts_argument_spec = spec[subspec][options]
            else:
                facts_argument_spec = spec[subspec]
        else:
            facts_argument_spec = spec

        self.generated_spec = utils.generate_dict(facts_argument_spec)

    def get_acls_config(self, connection):
        return connection.get("sh access-list")

    def populate_facts(self, connection, ansible_facts, data=None):
        """Populate the facts for ACLs
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if not data:
            data = self.get_acls_config(connection)

        rmmod = NetworkTemplate(lines=data.splitlines(), tmplt=AclsTemplate())
        current = rmmod.parse()
        acls = list()
        if current.get("acls"):
            for key, val in iteritems(current.get("acls")):
                if val.get("name") == "cached":
                    continue
                for each in val.get("aces"):
                    if "protocol_number" in each:
                        each["protocol_options"] = {
                            "protocol_number": each["protocol_number"],
                        }
                        del each["protocol_number"]
                    if "icmp_icmp6_protocol" in each and each.get("protocol"):
                        each["protocol_options"] = {
                            each.get("protocol"): {
                                each["icmp_icmp6_protocol"].replace(
                                    "-",
                                    "_",
                                ): True,
                            },
                        }
                        del each["icmp_icmp6_protocol"]
                    elif (
                        each.get("protocol")
                        and each.get("protocol") != "icmp"
                        and each.get("protocol") != "icmp6"
                    ):
                        each["protocol_options"] = {each.get("protocol"): True}
                acls.append(val)
        facts = {}
        params = {}
        if acls:
            params = utils.validate_config(
                self.argument_spec,
                {"config": {"acls": acls}},
            )
            params = utils.remove_empties(params)
            facts["acls"] = params["config"]

        ansible_facts["ansible_network_resources"].update(facts)
        return ansible_facts

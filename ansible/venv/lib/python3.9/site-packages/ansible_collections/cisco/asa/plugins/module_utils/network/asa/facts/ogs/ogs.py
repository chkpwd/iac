# -*- coding: utf-8 -*-
# Copyright 2019 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The asa_og fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type


from ansible.module_utils.six import iteritems
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.network_template import (
    NetworkTemplate,
)

from ansible_collections.cisco.asa.plugins.module_utils.network.asa.argspec.ogs.ogs import OGsArgs
from ansible_collections.cisco.asa.plugins.module_utils.network.asa.rm_templates.ogs import (
    OGsTemplate,
)


class OGsFacts(object):
    """The asa_ogs fact class"""

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = OGsArgs.argument_spec

    def get_og_data(self, connection):
        return connection.get("sh running-config object-group")

    def populate_facts(self, connection, ansible_facts, data=None):
        """Populate the facts for OGs
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if not data:
            data = self.get_og_data(connection)
        rmmod = NetworkTemplate(lines=data.splitlines(), tmplt=OGsTemplate())
        current = rmmod.parse()
        ogs = []
        object_groups = {
            "icmp-type": "icmp_type",
            "network": "network_object",
            "protocol": "protocol_object",
            "security": "security_group",
            "service": "service_object",
            "user": "user_object",
        }
        if current.get("ogs"):
            for k, v in iteritems(current.get("ogs")):
                obj_gp = {}
                config_dict = {}
                config_dict["object_type"] = k
                config_dict["object_groups"] = []
                for each in iteritems(v):
                    obj_gp["name"] = each[1].pop("name")
                    each[1].pop("object_type")
                    if each[1].get("description"):
                        obj_gp["description"] = each[1].pop("description")
                    if each[1].get("group_object"):
                        obj_gp["group_object"] = each[1].pop("group_object")
                    if k == "service":
                        if "services_object" in each[1]:
                            obj_gp["services_object"] = each[1]["services_object"]
                        elif "port_object" in each[1]:
                            obj_gp["port_object"] = each[1]["port_object"]
                            obj_gp["protocol"] = each[1]["protocol"]
                    else:
                        obj_gp[object_groups.get(k)] = each[1]
                    config_dict["object_groups"].append(obj_gp)
                    obj_gp = {}
                config_dict["object_groups"] = sorted(
                    config_dict["object_groups"],
                    key=lambda k, sk="name": str(k[sk]),
                )
                ogs.append(config_dict)
        # sort the object group list of dict by object_type
        ogs = sorted(ogs, key=lambda i: i["object_type"])
        facts = {}
        params = utils.remove_empties(
            utils.validate_config(self.argument_spec, {"config": ogs}),
        )
        facts["ogs"] = params.get("config")

        ansible_facts["ansible_network_resources"].update(facts)
        return ansible_facts

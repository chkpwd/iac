#
# -*- coding: utf-8 -*-
# Copyright 2019 Red Hat Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The asa_ogs class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

import copy

from ansible.module_utils.six import iteritems
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.resource_module import (
    ResourceModule,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    dict_merge,
)

from ansible_collections.cisco.asa.plugins.module_utils.network.asa.facts.facts import Facts
from ansible_collections.cisco.asa.plugins.module_utils.network.asa.rm_templates.ogs import (
    OGsTemplate,
)


class OGs(ResourceModule):
    """
    The asa_ogs class
    """

    gather_subset = ["!all", "!min"]

    gather_network_resources = ["ogs"]

    def __init__(self, module):
        super(OGs, self).__init__(
            empty_fact_val={},
            facts_module=Facts(module),
            module=module,
            resource="ogs",
            tmplt=OGsTemplate(),
        )

    def execute_module(self):
        """Execute the module
        :rtype: A dictionary
        :returns: The result from module execution
        """
        self.gen_config()
        self.run_commands()
        return self.result

    def gen_config(self):
        """Select the appropriate function based on the state provided
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        if self.want:
            temp = {}
            for entry in self.want:
                temp.update({(entry["object_type"]): entry})
            wantd = temp
        else:
            wantd = {}
        if self.have:
            temp = {}
            for entry in self.have:
                temp.update({(entry["object_type"]): entry})
            haved = temp
        else:
            haved = {}

        obj_gp = {}
        for k, v in wantd.items():
            temp = {}
            for each in v.get("object_groups"):
                temp[each.get("name")] = each
                temp["object_type"] = k
                obj_gp[k] = temp
        if obj_gp:
            wantd = obj_gp
            obj_gp = {}
        for k, v in haved.items():
            temp = {}
            for each in v.get("object_groups"):
                temp[each.get("name")] = each
                temp["object_type"] = k
                obj_gp[k] = temp
        if obj_gp:
            haved = obj_gp

        # if state is merged, merge want onto have
        if self.state == "merged":
            wantd = dict_merge(haved, wantd)

        # if state is deleted, empty out wantd and set haved to wantd
        if self.state == "deleted":
            temp = {}
            for k, v in iteritems(haved):
                temp_have = {}
                if k in wantd or not wantd:
                    for key, val in iteritems(v):
                        if not wantd or key in wantd[k]:
                            temp_have.update({key: val})
                    temp.update({k: temp_have})
            haved = temp
            wantd = {}

        # delete processes first so we do run into "more than one" errors
        if self.state in ["overridden", "deleted"]:
            for k, have in iteritems(haved):
                if k not in wantd:
                    for each_key, each_val in iteritems(have):
                        if each_key != "object_type":
                            each_val.update(
                                {"object_type": have.get("object_type")},
                            )
                            self.addcmd(each_val, "og_name", True)

        for k, want in iteritems(wantd):
            self._compare(want=want, have=haved.pop(k, {}))

    def _compare(self, want, have):
        if want != have:
            for k, v in iteritems(want):
                if k != "object_type":
                    v.update({"object_type": want.get("object_type")})
            if have:
                for k, v in iteritems(have):
                    if k != "object_type":
                        v.update({"object_type": want.get("object_type")})

            object_type = want.get("object_type")
            if object_type == "icmp-type":
                self._icmp_object_compare(want, have)
            if object_type == "network":
                self._network_object_compare(want, have)
            elif object_type == "protocol":
                self._protocol_object_compare(want, have)
            elif object_type == "security":
                self._security_object_compare(want, have)
            elif object_type == "service":
                self._service_object_compare(want, have)
            elif object_type == "user":
                self._user_object_compare(want, have)

    def get_list_diff(self, want, have, object, param):
        diff = [item for item in want[object][param] if item not in have[object][param]]
        return diff

    def check_for_have_and_overidden(self, have):
        if have and self.state == "overridden":
            for name, entry in iteritems(have):
                if name != "object_type":
                    self.addcmd(entry, "og_name", True)

    def _icmp_object_compare(self, want, have):
        icmp_obj = "icmp_type"
        for name, entry in iteritems(want):
            h_item = have.pop(name, {})
            if entry != h_item and name != "object_type" and entry[icmp_obj].get("icmp_object"):
                if h_item and entry.get("group_object"):
                    self.addcmd(entry, "og_name", False)
                    self._add_group_object_cmd(entry, h_item)
                    continue
                if h_item:
                    self._add_object_cmd(
                        entry,
                        h_item,
                        icmp_obj,
                        ["icmp_type"],
                    )
                else:
                    self.addcmd(entry, "og_name", False)
                    self.compare(["description"], entry, h_item)
                if entry.get("group_object"):
                    self._add_group_object_cmd(entry, h_item)
                    continue
                if self.state in ("overridden", "replaced") and h_item:
                    self.compare(["icmp_type"], {}, h_item)
                if h_item and h_item[icmp_obj].get("icmp_object"):
                    li_diff = self.get_list_diff(
                        entry,
                        h_item,
                        icmp_obj,
                        "icmp_object",
                    )
                else:
                    li_diff = entry[icmp_obj].get("icmp_object")
                entry[icmp_obj]["icmp_object"] = li_diff
                self.addcmd(entry, "icmp_type", False)
        self.check_for_have_and_overidden(have)

    def _network_object_compare(self, want, have):
        network_obj = "network_object"
        parsers = [
            "network_object.host",
            "network_object.address",
            "network_object.ipv6_address",
            "network_object.object",
        ]
        add_obj_cmd = False
        for name, entry in iteritems(want):
            h_item = have.pop(name, {})
            if entry != h_item and name != "object_type":
                if h_item and entry.get("group_object"):
                    self.addcmd(entry, "og_name", False)
                    self._add_group_object_cmd(entry, h_item)
                    continue
                if h_item:
                    self._add_object_cmd(
                        entry,
                        h_item,
                        network_obj,
                        ["address", "host", "ipv6_address", "object"],
                    )
                else:
                    add_obj_cmd = True
                    self.addcmd(entry, "og_name", False)
                    self.compare(["description"], entry, h_item)
                if entry.get("group_object"):
                    self._add_group_object_cmd(entry, h_item)
                    continue
                if entry[network_obj].get("address"):
                    self._compare_object_diff(
                        entry,
                        h_item,
                        network_obj,
                        "address",
                        parsers,
                        "network_object.address",
                    )
                elif h_item and h_item.get(network_obj) and h_item[network_obj].get("address"):
                    h_item[network_obj] = {
                        "address": h_item[network_obj].get("address"),
                    }
                    if not add_obj_cmd:
                        self.addcmd(entry, "og_name", False)
                    self.compare(parsers, {}, h_item)
                if entry[network_obj].get("host"):
                    self._compare_object_diff(
                        entry,
                        h_item,
                        network_obj,
                        "host",
                        parsers,
                        "network_object.host",
                    )
                elif h_item and h_item[network_obj].get("host"):
                    h_item[network_obj] = {
                        "host": h_item[network_obj].get("host"),
                    }
                    if not add_obj_cmd:
                        self.addcmd(entry, "og_name", False)
                    self.compare(parsers, {}, h_item)
                if entry[network_obj].get("ipv6_address"):
                    self._compare_object_diff(
                        entry,
                        h_item,
                        network_obj,
                        "ipv6_address",
                        parsers,
                        "network_object.ipv6_address",
                    )
                elif h_item and h_item.get(network_obj) and h_item[network_obj].get("ipv6_address"):
                    h_item[network_obj] = {
                        "ipv6_address": h_item[network_obj].get("ipv6_address"),
                    }
                    if not add_obj_cmd:
                        self.addcmd(entry, "og_name", False)
                    self.compare(parsers, {}, h_item)
                if entry[network_obj].get("object"):
                    self._compare_object_diff(
                        entry,
                        h_item,
                        network_obj,
                        "object",
                        parsers,
                        "network_object.object",
                    )
                elif h_item and h_item.get(network_obj) and h_item[network_obj].get("object"):
                    h_item[network_obj] = {
                        "object": h_item[network_obj].get("object"),
                    }
                    if not add_obj_cmd:
                        self.addcmd(entry, "og_name", False)
                    self.compare(parsers, {}, h_item)
        self.check_for_have_and_overidden(have)

    def _protocol_object_compare(self, want, have):
        protocol_obj = "protocol_object"
        for name, entry in iteritems(want):
            h_item = have.pop(name, {})
            if entry != h_item and name != "object_type":
                if h_item and entry.get("group_object"):
                    self.addcmd(entry, "og_name", False)
                    self._add_group_object_cmd(entry, h_item)
                    continue
                if h_item:
                    self._add_object_cmd(
                        entry,
                        h_item,
                        protocol_obj,
                        ["protocol"],
                    )
                else:
                    self.addcmd(entry, "og_name", False)
                    self.compare(["description"], entry, h_item)
                if entry.get("group_object"):
                    self._add_group_object_cmd(entry, h_item)
                    continue
                if entry[protocol_obj].get("protocol"):
                    self._compare_object_diff(
                        entry,
                        h_item,
                        protocol_obj,
                        "protocol",
                        [protocol_obj],
                        protocol_obj,
                    )
        self.check_for_have_and_overidden(have)

    def _security_object_compare(self, want, have):
        security_obj = "security_group"
        parsers = ["security_group.sec_name", "security_group.tag"]
        add_obj_cmd = False
        for name, entry in iteritems(want):
            h_item = have.pop(name, {})
            if entry != h_item and name != "object_type":
                if h_item and entry.get("group_object"):
                    self.addcmd(entry, "og_name", False)
                    self._add_group_object_cmd(entry, h_item)
                    continue
                if h_item:
                    self._add_object_cmd(
                        entry,
                        h_item,
                        security_obj,
                        ["sec_name", "tag"],
                    )
                else:
                    add_obj_cmd = True
                    self.addcmd(entry, "og_name", False)
                    self.compare(["description"], entry, h_item)
                if entry.get("group_object"):
                    self._add_group_object_cmd(entry, h_item)
                    continue
                if entry[security_obj].get("sec_name"):
                    self._compare_object_diff(
                        entry,
                        h_item,
                        security_obj,
                        "sec_name",
                        parsers,
                        "security_group.sec_name",
                    )
                elif h_item and h_item[security_obj].get("sec_name"):
                    h_item[security_obj] = {
                        "sec_name": h_item[security_obj].get("sec_name"),
                    }
                    if not add_obj_cmd:
                        self.addcmd(entry, "og_name", False)
                    self.compare(parsers, {}, h_item)
                if entry[security_obj].get("tag"):
                    self._compare_object_diff(
                        entry,
                        h_item,
                        security_obj,
                        "tag",
                        parsers,
                        "security_group.tag",
                    )
                elif h_item and h_item[security_obj].get("tag"):
                    h_item[security_obj] = {
                        "tag": h_item[security_obj].get("tag"),
                    }
                    if not add_obj_cmd:
                        self.addcmd(entry, "og_name", False)
                    self.compare(parsers, {}, h_item)
        self.check_for_have_and_overidden(have)

    def _service_object_compare(self, want, have):
        service_obj = "service_object"
        services_obj = "services_object"
        port_obj = "port_object"
        for name, entry in iteritems(want):
            h_item = have.pop(name, {})
            if entry != h_item and name != "object_type":
                if h_item and entry.get("group_object"):
                    self.addcmd(entry, "og_name", False)
                    self._add_group_object_cmd(entry, h_item)
                    continue
                if h_item:
                    self._add_object_cmd(
                        entry,
                        h_item,
                        service_obj,
                        ["protocol"],
                    )
                else:
                    protocol = entry.get("protocol")
                    if protocol:
                        entry["name"] = "{0} {1}".format(name, protocol)
                    self.addcmd(entry, "og_name", False)
                    self.compare(["description"], entry, h_item)
                if entry.get("group_object"):
                    self._add_group_object_cmd(entry, h_item)
                    continue
                if entry.get(service_obj):
                    if entry[service_obj].get("protocol"):
                        self._compare_object_diff(
                            entry,
                            h_item,
                            service_obj,
                            "protocol",
                            ["service_object"],
                            service_obj,
                        )
                elif entry.get(services_obj):
                    if h_item:
                        h_item = self.convert_list_to_dict(
                            val=h_item,
                            source="source_port",
                            destination="destination_port",
                        )
                    entry = self.convert_list_to_dict(
                        val=entry,
                        source="source_port",
                        destination="destination_port",
                    )
                    command_len = len(self.commands)
                    for k, v in iteritems(entry):
                        if h_item:
                            h_service_item = h_item.pop(k, {})
                            if h_service_item != v:
                                self.compare(
                                    [services_obj],
                                    want={services_obj: v},
                                    have={services_obj: h_service_item},
                                )
                        else:
                            temp_want = {"name": name, services_obj: v}
                            self.addcmd(temp_want, "og_name", True)

                            self.compare(
                                [services_obj],
                                want=temp_want,
                                have={},
                            )
                    if h_item and self.state in ["overridden", "replaced"]:
                        for k, v in iteritems(h_item):
                            temp_have = {"name": name, services_obj: v}
                            self.compare(
                                [services_obj],
                                want={},
                                have=temp_have,
                            )
                    if command_len < len(self.commands):
                        cmd = "object-group service {0}".format(name)
                        if cmd not in self.commands:
                            self.commands.insert(command_len, cmd)
                elif entry.get(port_obj):
                    protocol = entry.get("protocol")
                    if h_item:
                        h_item = self.convert_list_to_dict(
                            val=h_item,
                            source="source_port",
                            destination="destination_port",
                        )
                    entry = self.convert_list_to_dict(
                        val=entry,
                        source="source_port",
                        destination="destination_port",
                    )
                    command_len = len(self.commands)
                    for k, v in iteritems(entry):
                        h_port_item = h_item.pop(k, {})
                        if "http" in k and "_" in k:
                            # This condition is to TC of device behaviour, where if user tries to
                            # configure http it gets converted to www.
                            temp = k.split("_")[0]
                            h_port_item = {temp: "http"}
                        if h_port_item != v:
                            self.compare(
                                [port_obj],
                                want={port_obj: v},
                                have={port_obj: h_port_item},
                            )
                        elif not h_port_item:
                            temp_want = {"name": name, port_obj: v}
                            self.compare([port_obj], want=temp_want, have={})
                    if h_item and self.state in ["overridden", "replaced"]:
                        for k, v in iteritems(h_item):
                            temp_have = {"name": name, port_obj: v}
                            self.compare([port_obj], want={}, have=temp_have)
        self.check_for_have_and_overidden(have)

    def convert_list_to_dict(self, *args, **kwargs):
        temp = {}
        if kwargs["val"].get("services_object"):
            for every in kwargs["val"]["services_object"]:
                temp_key = every["protocol"]
                if "source_port" in every:
                    if "range" in every["source_port"]:
                        temp_key = (
                            "range"
                            + "_"
                            + str(every["source_port"]["range"]["start"])
                            + "_"
                            + str(every["source_port"]["range"]["end"])
                        )
                    else:
                        source_key = list(every["source_port"])[0]
                        temp_key = (
                            temp_key + "_" + source_key + "_" + every["source_port"][source_key]
                        )
                if "destination_port" in every:
                    if "range" in every["destination_port"]:
                        temp_key = (
                            "range"
                            + "_"
                            + str(every["destination_port"]["range"]["start"])
                            + "_"
                            + str(every["destination_port"]["range"]["end"])
                        )
                    else:
                        destination_key = list(every["destination_port"])[0]
                        temp_key = (
                            temp_key
                            + "_"
                            + destination_key
                            + "_"
                            + every["destination_port"][destination_key]
                        )
                temp.update({temp_key: every})
            return temp
        elif kwargs["val"].get("port_object"):
            for every in kwargs["val"]["port_object"]:
                if "range" in every:
                    temp_key = (
                        "start"
                        + "_"
                        + every["range"]["start"]
                        + "_"
                        + "end"
                        + "_"
                        + every["range"]["end"]
                    )
                else:
                    every_key = list(every)[0]
                    temp_key = every_key + "_" + every[every_key]
                temp.update({temp_key: every})
            return temp

    def _user_object_compare(self, want, have):
        user_obj = "user_object"
        parsers = ["user_object.user", "user_object.user_gp"]
        add_obj_cmd = False
        for name, entry in iteritems(want):
            h_item = have.pop(name, {})
            if entry != h_item and name != "object_type":
                if h_item and entry.get("group_object"):
                    self.addcmd(entry, "og_name", False)
                    self._add_group_object_cmd(entry, h_item)
                    continue
                if h_item:
                    self._add_object_cmd(
                        entry,
                        h_item,
                        user_obj,
                        ["user", "user_group"],
                    )
                else:
                    add_obj_cmd = True
                    self.addcmd(entry, "og_name", False)
                    self.compare(["description"], entry, h_item)
                if entry.get("group_object"):
                    self._add_group_object_cmd(entry, h_item)
                    continue
                if entry[user_obj].get("user"):
                    self._compare_object_diff(
                        entry,
                        h_item,
                        user_obj,
                        "user",
                        ["user_object.user"],
                        "user_object.user",
                    )
                elif h_item and h_item[user_obj].get("user"):
                    h_item[user_obj] = {"user": h_item[user_obj].get("user")}
                    if not add_obj_cmd:
                        self.addcmd(entry, "og_name", False)
                    self.compare(parsers, {}, h_item)
                if entry[user_obj].get("user_group"):
                    self._compare_object_diff(
                        entry,
                        h_item,
                        user_obj,
                        "user_group",
                        ["user_object.user_group"],
                        "user_object.user_gp",
                    )
                elif h_item and h_item[user_obj].get("user_group"):
                    h_item[user_obj] = {
                        "user_group": h_item[user_obj].get("user_group"),
                    }
                    if not add_obj_cmd:
                        self.addcmd(entry, "og_name", False)
                    self.compare(parsers, {}, h_item)
        self.check_for_have_and_overidden(have)

    def _add_object_cmd(self, want, have, object, object_elements):
        obj_cmd_added = False
        for each in object_elements:
            want_element = want[object].get(each) if want.get(object) else want
            have_element = have[object].get(each) if have.get(object) else have
            if (
                want_element
                and isinstance(want_element, list)
                and isinstance(want_element[0], dict)
            ):
                if want_element and have_element and want_element != have_element:
                    if not obj_cmd_added:
                        self.addcmd(want, "og_name", False)
                        self.compare(["description"], want, have)
                        obj_cmd_added = True
            else:
                if want_element and have_element and set(want_element) != set(have_element):
                    if not obj_cmd_added:
                        self.addcmd(want, "og_name", False)
                        self.compare(["description"], want, have)
                        obj_cmd_added = True

    def _add_group_object_cmd(self, want, have):
        if have and have.get("group_object"):
            want["group_object"] = list(
                set(want.get("group_object")) - set(have.get("group_object")),
            )
            have["group_object"] = list(
                set(have.get("group_object")) - set(want.get("group_object")),
            )
        for each in want["group_object"]:
            self.compare(["group_object"], {"group_object": each}, dict())
        if (
            (self.state == "replaced" or self.state == "overridden")
            and have
            and have.get("group_object")
        ):
            for each in have["group_object"]:
                self.compare(["group_object"], dict(), {"group_object": each})

    def _compare_object_diff(
        self,
        want,
        have,
        object,
        object_type,
        parsers,
        val,
    ):
        temp_have = copy.copy(have)
        temp_want = copy.copy(want)
        if temp_have and temp_have.get(object) and temp_have[object].get(object_type):
            want_diff = self.get_list_diff(
                temp_want,
                temp_have,
                object,
                object_type,
            )
            have_diff = [
                each
                for each in temp_have[object][object_type]
                if each not in temp_want[object][object_type]
            ]
            if have_diff:
                temp_have[object].pop(object_type)
        else:
            have_diff = []
            want_diff = temp_want[object].get(object_type)
        temp_want[object][object_type] = want_diff
        if have_diff or temp_have.get(object) and self.state in ("overridden", "replaced"):
            if have_diff:
                temp_have[object] = {object_type: have_diff}
                self.compare(parsers, {}, temp_have)
        self.addcmd(temp_want, val, False)

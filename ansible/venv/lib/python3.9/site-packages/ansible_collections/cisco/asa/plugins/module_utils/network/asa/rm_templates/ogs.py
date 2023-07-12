from __future__ import absolute_import, division, print_function


__metaclass__ = type

import re

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.network_template import (
    NetworkTemplate,
)


def _tmplt_object_group(config_data):
    command = "object-group {object_type} {name}".format(**config_data)
    return command


def _tmplt_icmp_object(config_data):
    commands = []
    if config_data.get("icmp_type").get("icmp_object"):
        for each in config_data.get("icmp_type").get("icmp_object"):
            commands.append("icmp-object {0}".format(each))
        return commands


def _tmplt_network_object(config_data):
    commands = []
    if config_data.get("network_object").get("host"):
        for each in config_data.get("network_object").get("host"):
            commands.append("network-object host {0}".format(each))
        return commands


def _tmplt_network_object_address(config_data):
    commands = []
    if config_data.get("network_object").get("address"):
        for each in config_data.get("network_object").get("address"):
            commands.append("network-object {0}".format(each))
        return commands


def _tmplt_network_object_ipv6(config_data):
    commands = []
    if config_data.get("network_object").get("ipv6_address"):
        for each in config_data.get("network_object").get("ipv6_address"):
            commands.append("network-object {0}".format(each))
        return commands


def _tmplt_network_object_object(config_data):
    commands = []
    if config_data.get("network_object").get("object"):
        for each in config_data.get("network_object").get("object"):
            commands.append("network-object object {0}".format(each))
        return commands


def _tmplt_protocol_object(config_data):
    commands = []
    if config_data.get("protocol_object").get("protocol"):
        for each in config_data.get("protocol_object").get("protocol"):
            commands.append("protocol {0}".format(each))
        return commands


def _tmplt_sec_group_name(config_data):
    commands = []
    if config_data.get("security_group").get("sec_name"):
        for each in config_data.get("security_group").get("sec_name"):
            commands.append("security-group name {0}".format(each))
        return commands


def _tmplt_sec_group_tag(config_data):
    commands = []
    if config_data.get("security_group").get("tag"):
        for each in config_data.get("security_group").get("tag"):
            commands.append("security-group tag {0}".format(each))
        return commands


def _tmplt_service_object(config_data):
    if config_data.get("service_object").get("protocol"):
        commands = []
        for each in config_data.get("service_object").get("protocol"):
            commands.append("service-object {0}".format(each))
        return commands


def _tmplt_services_object(config_data):
    if config_data.get("services_object"):
        cmd = "service-object {protocol}".format(**config_data["services_object"])
        if config_data["services_object"].get("source_port"):
            if config_data["services_object"]["source_port"].get("range"):
                cmd += " source range {start} {end}".format(
                    **config_data["services_object"]["source_port"]["range"]
                )
            else:
                key = list(config_data["services_object"]["source_port"])[0]
                cmd += " source {0} {1}".format(
                    key,
                    config_data["services_object"]["source_port"][key],
                )
        if config_data["services_object"].get("destination_port"):
            if config_data["services_object"]["destination_port"].get("range"):
                cmd += " destination range {start} {end}".format(
                    **config_data["services_object"]["destination_port"]["range"]
                )
            else:
                key = list(config_data["services_object"]["destination_port"])[0]
                cmd += " destination {0} {1}".format(
                    key,
                    config_data["services_object"]["destination_port"][key],
                )
        return cmd


def _tmplt_port_object(config_data):
    if config_data.get("port_object"):
        cmd = "port-object"
        if config_data["port_object"].get("range"):
            cmd += " range {start} {end}".format(**config_data["port_object"]["range"])
        else:
            key = list(config_data["port_object"])[0]
            cmd += " {0} {1}".format(key, config_data["port_object"][key])
        return cmd


def _tmplt_user_object_user(config_data):
    commands = []
    if config_data.get("user_object").get("user"):
        for each in config_data.get("user_object").get("user"):
            commands.append("user {domain}\\{name}".format(**each))
    return commands


def _tmplt_user_object_user_gp(config_data):
    commands = []
    if config_data.get("user_object").get("user_group"):
        for each in config_data.get("user_object").get("user_group"):
            commands.append(r"user-group {domain}\\{name}".format(**each))
    return commands


def _tmplt_group_object(config_data):
    command = "group-object {group_object}".format(**config_data)
    return command


class OGsTemplate(NetworkTemplate):
    def __init__(self, lines=None):
        super(OGsTemplate, self).__init__(lines=lines, tmplt=self)

    PARSERS = [
        {
            "name": "og_name",
            "getval": re.compile(
                r"""
                    ^object-group*
                    \s*(?P<obj_type>\S+)*
                    \s*(?P<obj_name>\S+)*
                    \s*(?P<protocol>\S+)*
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_object_group,
            "result": {
                "ogs": {
                    "{{ obj_type }}": {
                        "{{ obj_name }}": {
                            "object_type": "{{ obj_type }}",
                            "name": "{{ obj_name }}",
                            "protocol": "{{ protocol }}",
                        },
                    },
                },
            },
            "shared": True,
        },
        {
            "name": "description",
            "getval": re.compile(
                r"""\s+description:*
                    \s*(?P<description>.+)
                    *$""",
                re.VERBOSE,
            ),
            "setval": "description {{ description }}",
            "result": {
                "ogs": {
                    "{{ obj_type }}": {
                        "{{ obj_name }}": {"description": "{{ description }}"},
                    },
                },
            },
        },
        {
            "name": "icmp_type",
            "getval": re.compile(
                r"""\s+icmp-object*
                    \s*(?P<object>\S+)
                    *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_icmp_object,
            "compval": "icmp_type",
            "result": {
                "ogs": {
                    "{{ obj_type }}": {
                        "{{ obj_name }}": {"icmp_object": ["{{ object }}"]},
                    },
                },
            },
        },
        {
            "name": "network_object.address",
            "getval": re.compile(
                r"""\s+network-object*
                    \s*(?P<address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})
                    *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_network_object_address,
            "compval": "network_object.address",
            "result": {
                "ogs": {
                    "{{ obj_type }}": {
                        "{{ obj_name }}": {"address": ["{{ address }}"]},
                    },
                },
            },
        },
        {
            "name": "network_object.ipv6_address",
            "getval": re.compile(
                r"""\s+network-object*
                    \s*(?P<ipv6>\S+::/\d+)
                    *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_network_object_ipv6,
            "compval": "network_object.ipv6_address",
            "result": {
                "ogs": {
                    "{{ obj_type }}": {
                        "{{ obj_name }}": {"ipv6_address": ["{{ ipv6 }}"]},
                    },
                },
            },
        },
        {
            "name": "network_object.host",
            "getval": re.compile(
                r"""\s+network-object*
                    \s*(?P<host_obj>host)*
                    \s*(?P<host_address>\S+)
                    *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_network_object,
            "compval": "network_object.host",
            "result": {
                "ogs": {
                    "{{ obj_type }}": {
                        "{{ obj_name }}": {"host": ["{{ host_address }}"]},
                    },
                },
            },
        },
        {
            "name": "network_object.object",
            "getval": re.compile(
                r"""\s+network-object\s
                    object*
                    \s*(?P<object>\S+)
                    *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_network_object_object,
            "compval": "network_object.object",
            "result": {
                "ogs": {
                    "{{ obj_type }}": {
                        "{{ obj_name }}": {"object": ["{{ object }}"]},
                    },
                },
            },
        },
        {
            "name": "protocol_object",
            "getval": re.compile(
                r"""\s+protocol-object*
                    \s*(?P<protocol>\S+)
                    *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_protocol_object,
            "compval": "protocol_object",
            "result": {
                "ogs": {
                    "{{ obj_type }}": {
                        "{{ obj_name }}": {"protocol": ["{{ protocol }}"]},
                    },
                },
            },
        },
        {
            "name": "security_group.sec_name",
            "getval": re.compile(
                r"""\s+security-group\s
                    name*
                    \s*(?P<name>\S+)
                    *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_sec_group_name,
            "compval": "security_group.sec_name",
            "result": {
                "ogs": {
                    "{{ obj_type }}": {
                        "{{ obj_name }}": {"sec_name": ["{{ name }}"]},
                    },
                },
            },
        },
        {
            "name": "security_group.tag",
            "getval": re.compile(
                r"""\s+security-group\s
                    tag*
                    \s*(?P<tag>\S+)
                    *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_sec_group_tag,
            "compval": "security_group.tag",
            "result": {
                "ogs": {
                    "{{ obj_type }}": {
                        "{{ obj_name }}": {"tag": ["{{ tag }}"]},
                    },
                },
            },
        },
        {
            "name": "port_object",
            "getval": re.compile(
                r"""\s+port-object*
                    \s*(?P<eq>eq\s\S+)*
                    \s*(?P<range>range\s(\S+|\d+)\s(\S+|\d+))
                    *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_port_object,
            "compval": "port_object",
            "result": {
                "ogs": {
                    "{{ obj_type }}": {
                        "{{ obj_name }}": {
                            "port_object": [
                                {
                                    "eq": "{{ eq.split(' ')[1] if eq is defined }}",
                                    "range": {
                                        "start": "{{ range.split('range ')[1].split(' ')[0] if range is defined else None }}",
                                        "end": "{{ range.split('range ')[1].split(' ')[1] if range is defined else None }}",
                                    },
                                },
                            ],
                        },
                    },
                },
            },
        },
        {
            "name": "services_object",
            "getval": re.compile(
                r"""\s+service-object*
                    \s*(?P<protocol>\S+)*
                    \s*(?P<source_port>source\s((eq|gts|lt|neq)\s(\S+|\d+)|(range\s(\S+|\S+)\s(\S+|\S+))))*
                    \s*(?P<destination_port>destination\s((eq|gt|lt|neq)\s(\S+|\d+)|(range\s(\S+|\S+)\s(\S+|\S+))))
                    *""",
                re.VERBOSE,
            ),
            "setval": _tmplt_services_object,
            "compval": "services_object",
            "result": {
                "ogs": {
                    "{{ obj_type }}": {
                        "{{ obj_name }}": {
                            "services_object": [
                                {
                                    "protocol": "{{ protocol }}",
                                    "source_port": {
                                        "eq": "{{ source_port.split(' ')[2] if source_port is defined and\
                                            'eq' in source_port and 'range' not in source_port }}",
                                        "gt": "{{ source_port.split(' ')[2] if source_port is defined and\
                                            'gt' in source_port and 'range' not in source_port }}",
                                        "lt": "{{ source_port.split(' ')[2] if source_port is defined and\
                                            'lt' in source_port and 'range' not in source_port }}",
                                        "neq": "{{ source_port.split(' ')[2] if source_port is defined and\
                                            'neq' in source_port and 'range' not in source_port }}",
                                        "range": {
                                            "start": "{{ source_port.split('range ')[1].split(' ')[0] if source_port is defined and\
                                                'range' in source_port else None }}",
                                            "end": "{{ source_port.split('range ')[1].split(' ')[1] if source_port is defined and\
                                                'range' in source_port else None }}",
                                        },
                                    },
                                    "destination_port": {
                                        "eq": "{{ destination_port.split(' ')[2] if destination_port is defined and\
                                            'eq' in destination_port and 'range' not in destination_port }}",
                                        "gt": "{{ destination_port.split(' ')[2] if destination_port is defined and\
                                            'gt' in destination_port and 'range' not in destination_port }}",
                                        "lt": "{{ destination_port.split(' ')[2] if destination_port is defined and\
                                            'lt' in destination_port and 'range' not in destination_port }}",
                                        "neq": "{{ destination_port.split(' ')[2] if destination_port is defined and\
                                            'neq' in destination_port and 'range' not in destination_port }}",
                                        "range": {
                                            "start": "{{ destination_port.split('range ')[1].split(' ')[0] if destination_port is defined and\
                                                'range' in destination_port else None }}",
                                            "end": "{{ destination_port.split('range ')[1].split(' ')[1] if destination_port is defined and\
                                                'range' in destination_port else None }}",
                                        },
                                    },
                                },
                            ],
                        },
                    },
                },
            },
        },
        {
            "name": "service_object.object",
            "getval": re.compile(
                r"""\s+service-object\s
                    object*
                    \s*(?P<object>\S+)
                    *$""",
                re.VERBOSE,
            ),
            "setval": "service-object object {{ object }}",
            "result": {
                "ogs": {
                    "{{ obj_type }}": {
                        "{{ obj_name }}": {"object": "{{ object }}"},
                    },
                },
            },
        },
        {
            "name": "service_object",
            "getval": re.compile(
                r"""\s+service-object*
                    \s*(?P<protocol>\S+)*\s
                    *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_service_object,
            "compval": "service_object",
            "result": {
                "ogs": {
                    "{{ obj_type }}": {
                        "{{ obj_name }}": {"protocol": ["{{ protocol }}"]},
                    },
                },
            },
        },
        {
            "name": "user_object.user",
            "getval": re.compile(
                r"""\s+user*
                    \s*(?P<domain>\S+)\\
                    (?P<user_name>\S+)
                    *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_user_object_user,
            "compval": "user_object",
            "result": {
                "ogs": {
                    "{{ obj_type }}": {
                        "{{ obj_name }}": {
                            "user": [
                                {
                                    "name": "{{ user_name }}",
                                    "domain": "{{ domain }}",
                                },
                            ],
                        },
                    },
                },
            },
        },
        {
            "name": "user_object.user_gp",
            "getval": re.compile(
                r"""\s+user-group*
                    \s*(?P<domain>\S+\\)
                    (?P<user_gp>\S+)
                    *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_user_object_user_gp,
            "compval": "user_object",
            "result": {
                "ogs": {
                    "{{ obj_type }}": {
                        "{{ obj_name }}": {
                            "user_group": [
                                {
                                    "name": "{{ user_gp }}",
                                    "domain": r"{{ domain.split('\\')[0] }}",
                                },
                            ],
                        },
                    },
                },
            },
        },
        {
            "name": "group_object",
            "getval": re.compile(
                r"""\s+group-object*
                    \s*(?P<gp_obj>\S+)
                    *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_group_object,
            "compval": "group_object",
            "result": {
                "ogs": {
                    "{{ obj_type }}": {
                        "{{ obj_name }}": {"group_object": ["{{ gp_obj }}"]},
                    },
                },
            },
        },
    ]

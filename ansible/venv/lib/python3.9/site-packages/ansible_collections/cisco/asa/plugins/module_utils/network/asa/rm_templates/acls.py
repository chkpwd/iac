from __future__ import absolute_import, division, print_function


__metaclass__ = type

import re

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.network_template import (
    NetworkTemplate,
)


def _tmplt_access_list_name(config_data):
    command = "access-list {acls_name} ".format(**config_data)
    return command


def _tmplt_access_list_entries(config_data):
    if "aces" in config_data:
        command = []

        def source_destination_common_config(config_data, cmd, type):
            if config_data["aces"][type].get("any"):
                cmd += " any"
            elif config_data["aces"][type].get("any4"):
                cmd += " any4"
            elif config_data["aces"][type].get("any6"):
                cmd += " any6"
            elif config_data["aces"][type].get("address"):
                cmd += " {address}".format(**config_data["aces"][type])
                if config_data["aces"][type].get("netmask"):
                    cmd += " {netmask}".format(**config_data["aces"][type])
            elif config_data["aces"][type].get("host"):
                cmd += " host {host}".format(**config_data["aces"][type])
            elif config_data["aces"][type].get("interface"):
                cmd += " interface {interface}".format(**config_data["aces"][type])
            elif config_data["aces"][type].get("object_group"):
                cmd += " object-group {object_group}".format(**config_data["aces"][type])
            if type == "destination" and config_data["aces"][type].get(
                "service_object_group",
            ):
                cmd += " object-group {service_object_group}".format(**config_data["aces"][type])
            if config_data["aces"].get("protocol_options"):
                protocol_option_key = list(
                    config_data["aces"]["protocol_options"],
                )[0]
                if (
                    isinstance(
                        config_data["aces"]["protocol_options"][protocol_option_key],
                        dict,
                    )
                    and type == "destination"
                ):
                    val = list(
                        config_data["aces"]["protocol_options"][protocol_option_key],
                    )[0]
                    cmd += " {0}".format(val.replace("_", "-"))
            if config_data["aces"][type].get("port_protocol"):
                if config_data["aces"][type].get("port_protocol").get("range"):
                    start = config_data["aces"][type].get("port_protocol")["range"]["start"]
                    end = config_data["aces"][type].get("port_protocol")["range"]["end"]
                    cmd += " range {0} {1}".format(start, end)
                else:
                    port_protocol = list(
                        config_data["aces"][type]["port_protocol"],
                    )[0]
                    cmd += (
                        " "
                        + port_protocol
                        + " "
                        + config_data["aces"][type]["port_protocol"][port_protocol]
                    )
            return cmd

        cmd = ""
        if config_data["aces"].get("remark"):
            command.append(
                "access-list {name} line {line} remark {remark}".format(**config_data["aces"]),
            )
        if len(config_data["aces"]) > 4:
            try:
                cmd = "access-list {name} line {line}".format(**config_data["aces"])
            except KeyError:
                cmd = "access-list {name}".format(**config_data["aces"])
            if (
                config_data["aces"].get("acl_type")
                and config_data["aces"].get("acl_type") != "standard"
            ):
                cmd += " {acl_type}".format(**config_data["aces"])
            if config_data["aces"].get("grant"):
                cmd += " {grant}".format(**config_data["aces"])
            if config_data["aces"].get("protocol_options"):
                if "protocol_number" in config_data["aces"]["protocol_options"]:
                    cmd += " {protocol_number}".format(**config_data["aces"]["protocol_options"])
                else:
                    cmd += " {0}".format(
                        list(config_data["aces"]["protocol_options"])[0],
                    )
            elif config_data["aces"].get("protocol"):
                cmd += " {protocol}".format(**config_data["aces"])
            if config_data["aces"].get("source"):
                cmd = source_destination_common_config(
                    config_data,
                    cmd,
                    "source",
                )
            if config_data["aces"].get("destination"):
                cmd = source_destination_common_config(
                    config_data,
                    cmd,
                    "destination",
                )
            if config_data["aces"].get("log"):
                cmd += " log {log}".format(**config_data["aces"])
            if config_data["aces"].get("inactive"):
                cmd += " inactive"
            if config_data["aces"].get("time_range"):
                cmd += " time-range {time_range}".format(**config_data["aces"])
            if cmd:
                command.append(cmd)
        return command


class AclsTemplate(NetworkTemplate):
    def __init__(self, lines=None):
        super(AclsTemplate, self).__init__(lines=lines, tmplt=self)

    PARSERS = [
        {
            "name": "acls_name",
            "getval": re.compile(
                r"""^access-list*
                    \s*(?P<acl_name>\S+);
                    \s*\S+\s*elements;
                    """,
                re.VERBOSE,
            ),
            "setval": _tmplt_access_list_name,
            "compval": "name",
            "result": {"acls": {"{{ acl_name }}": {"name": "{{ acl_name }}"}}},
            "shared": True,
        },
        {
            "name": "aces",
            "getval": re.compile(
                r"""^access-list*
                    \s*(?P<acl_name>\S+)*
                    \s*(?P<line>line\s\d+)*
                    \s*(?P<remark>remark\s\S.*)*
                    \s*(?P<ethertype>ethertype)*
                    \s*(?P<webtype>webtype)*
                    \s*(?P<acl_type>extended|standard)*
                    \s*(?P<grant>deny|permit)*
                    \s*(?P<ethertype_params>(dsap\s\S+)|bpdu|eii-ipx|ipx|mpls-unicast|mpls-multicast|isis|any\s)*
                    \s*(?P<std_dest>(host\s\S+)|any4|(?:[0-9]{1,3}\.){3}[0-9]{1,3}\s(?:[0-9]{1,3}\.){3}[0-9]{1,3})*
                    \s*(?P<protocol>ah|eigrp|esp|gre|icmp|icmp6|igmp|igrp|ip|ipinip|ipsec|nos|ospf|pcp|pim|pptp|sctp|snp|tcp|udp)*
                    \s*(?P<protocol_num>\d+\s)*
                    \s*(?P<source>any4|any6|any|([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})|(([a-f0-9:]+:+)+[a-f0-9]+\S+|host\s(([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})|(([a-f0-9:]+:+)+[a-f0-9]+)\S+)|interface\s\S+|object-group\s\S+))*
                    \s*(?P<source_port_protocol>(eq|gts|lt|neq)\s(\S+|\d+)|range\s\S+\s\S+)*
                    \s*(?P<destination>any4|any6|any|([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})|(([a-f0-9:]+:+)+[a-f0-9]+\S+|host\s(([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})|(([a-f0-9:]+:+)+[a-f0-9]+)\S+)|interface\s\S+|object-group\s\S+))*
                    \s*(?P<dest_svc_object_group>object-group\s\S+)*
                    \s*(?P<dest_port_protocol>(eq|gts|lt|neq)\s(\S+|\d+)|range\s\S+\s\S+)*
                    \s*(?P<icmp_icmp6_protocol>alternate-address|conversion-error|echo|echo-reply|information-reply|information-request|mask-reply|mask-request|membership-query|membership-reduction|membership-report|mobile-redirect|neighbor-advertisement|neighbor-redirect|neighbor-solicitation|parameter-problem|packet-too-big|redirect|router-advertisement|router-renumbering|router-solicitation|source-quench|source-route-failed|time-exceeded|timestamp-reply|timestamp-request|traceroute|unreachable)*
                    \s*(?P<log>log\s\S+)*
                    \s*(?P<time_range>time-range\s\S+)*
                    \s*(?P<inactive>inactive)*
                    """,
                re.VERBOSE,
            ),
            "setval": _tmplt_access_list_entries,
            "result": {
                "acls": {
                    "{{ acl_name }}": {
                        "name": "{{ acl_name }}",
                        "acl_type": "{{ acl_type if acl_type is defined }}",
                        "aces": [
                            {
                                "grant": "{{ grant }}",
                                "line": "{{ line.split(' ')[1] if line is defined }}",
                                "remark": "{{ remark.split('remark ')[1] if remark is defined }}",
                                "protocol": "{{ protocol if protocol is defined else None }}",
                                "protocol_number": "{{ protocol_num if protocol_num is defined }}",
                                "icmp_icmp6_protocol": "{{ icmp_icmp6_protocol if icmp_icmp6_protocol is defined else None }}",
                                "source": {
                                    "address": "{% if source is defined and '.' in source and 'host'\
                                        not in source and 'object-group' not in source %}{{ source.split(' ')[0] }}{% elif source is defined and\
                                            '::' in source and 'host' not in source %}{{ source }}{% endif %}",
                                    "netmask": "{{ source.split(' ')[1] if source\
                                        is defined and '.' in source and 'host' not in source else None and 'object-group' not in source }}",
                                    "any4": "{{ True if source is defined and source == 'any4' else None }}",
                                    "any6": "{{ True if source is defined and source == 'any6' else None }}",
                                    "any": "{{ True if source is defined and source == 'any' else None }}",
                                    "host": "{{ source.split(' ')[1] if source is defined and 'host' in source else None }}",
                                    "interface": "{{ source.split(' ')[1] if source is defined and 'interface' in source else None }}",
                                    "object_group": "{{ source.split(' ')[1] if source is defined and 'object-group' in source else None }}",
                                    "port_protocol": {
                                        "{{ source_port_protocol.split(' ')[0] if source_port_protocol\
                                            is defined and 'range' not in source_port_protocol else None }}": "{{ source_port_protocol.split(' ')[1]\
                                                if source_port_protocol is defined and 'range' not in source_port_protocol else None }}",
                                        "{{ 'range' }}": {
                                            "start": "{{ source_port_protocol.split(' ')[1] if source_port_protocol is defined and\
                                                'range' in source_port_protocol else None }}",
                                            "end": "{{ source_port_protocol.split(' ')[2] if source_port_protocol is defined and\
                                                'range' in source_port_protocol else None }}",
                                        },
                                    },
                                },
                                "destination": {
                                    "address": "{% if destination is defined and 'host' not in destination and\
                                        '.' in destination and\
                                            'object-group' not in destination %}{{ destination.split(' ')[0] }}{% elif std_dest is defined and\
                                            '.' in std_dest and 'host' not in std_dest %}{{ std_dest.split(' ')[0] }}{% elif destination is defined and\
                                                 '::' in destination %}{{ destination }}{% endif %}",
                                    "netmask": "{% if destination is defined and 'host' not in destination and\
                                        '.' in destination and\
                                             'object-group' not in destination %}{{ destination.split(' ')[1] }}{% elif std_dest is defined and\
                                             '.' in std_dest and 'host' not in std_dest %}{{ std_dest.split(' ')[1] }}{% endif %}",
                                    "any4": "{% if destination is defined and\
                                         destination == 'any4' %}{{ True }}{% elif std_dest is defined and std_dest == 'any4' %}{{ True }}{% endif %}",
                                    "any6": "{{ True if destination is defined and destination == 'any6' else None }}",
                                    "any": "{{ True if destination is defined and destination == 'any' else None }}",
                                    "host": "{% if destination is defined and\
                                         'host' in destination %}{{ destination.split(' ')[1] }}{% elif std_dest is defined and\
                                              'host' in std_dest %}{{ std_dest.split(' ')[1] }}{% endif %}",
                                    "interface": "{{ destination.split(' ')[1] if destination is defined and 'interface' in destination else None }}",
                                    "object_group": "{{ destination.split(' ')[1] if destination is defined and 'object-group' in destination else None }}",
                                    "service_object_group": "{{ dest_svc_object_group.split('object-group ')[1] if dest_svc_object_group is defined }}",
                                    "port_protocol": {
                                        "{{ dest_port_protocol.split(' ')[0] if dest_port_protocol\
                                            is defined and 'range' not in dest_port_protocol else None }}": "{{ dest_port_protocol.split(' ')[1]\
                                                if dest_port_protocol is defined and 'range' not in dest_port_protocol else None }}",
                                        "{{ 'range' }}": {
                                            "start": "{{ dest_port_protocol.split(' ')[1] if dest_port_protocol is defined and\
                                                'range' in dest_port_protocol }}",
                                            "end": "{{ dest_port_protocol.split(' ')[2] if dest_port_protocol is defined and\
                                                'range' in dest_port_protocol }}",
                                        },
                                    },
                                },
                                "inactive": "{{ True if inactive is defined }}",
                                "log": "{{ log.split('log ')[1] if log is defined }}",
                                "time_range": "{{ time_range if time_range is defined }}",
                            },
                        ],
                    },
                },
            },
        },
    ]

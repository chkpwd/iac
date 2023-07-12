#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2023 Fortinet, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fmgr_fsp_vlan
short_description: no description
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.0.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded

options:
    access_token:
        description: The token to access FortiManager without using username and password.
        required: false
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        required: false
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        required: false
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        required: false
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        required: false
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        required: false
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        required: false
        elements: int
    state:
        description: The directive to create, update or delete an object.
        type: str
        required: true
        choices:
          - present
          - absent
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        required: false
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        required: false
        type: int
        default: 300
    adom:
        description: the parameter (adom) in requested url
        type: str
        required: true
    fsp_vlan:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            _dhcp-status:
                type: str
                description: _Dhcp-Status.
                choices:
                    - 'disable'
                    - 'enable'
            auth:
                type: str
                description: no description
                choices:
                    - 'radius'
                    - 'usergroup'
            color:
                type: int
                description: Color.
            comments:
                type: str
                description: no description
            dynamic_mapping:
                description: Dynamic_Mapping.
                type: list
                elements: dict
                suboptions:
                    _dhcp-status:
                        type: str
                        description: _Dhcp-Status.
                        choices:
                            - 'disable'
                            - 'enable'
                    _scope:
                        description: _Scope.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                type: str
                                description: Name.
                            vdom:
                                type: str
                                description: Vdom.
                    dhcp-server:
                        description: no description
                        type: dict
                        required: false
                        suboptions:
                            auto-configuration:
                                type: str
                                description: Enable/disable auto configuration.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            auto-managed-status:
                                type: str
                                description: Enable/disable use of this DHCP server once this interface has been assigned an IP address from FortiIPAM.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            conflicted-ip-timeout:
                                type: int
                                description: Time in seconds to wait after a conflicted IP address is removed from the DHCP range before it can be reused.
                            ddns-auth:
                                type: str
                                description: DDNS authentication mode.
                                choices:
                                    - 'disable'
                                    - 'tsig'
                            ddns-key:
                                type: str
                                description: DDNS update key
                            ddns-keyname:
                                type: str
                                description: DDNS update key name.
                            ddns-server-ip:
                                type: str
                                description: DDNS server IP.
                            ddns-ttl:
                                type: int
                                description: TTL.
                            ddns-update:
                                type: str
                                description: Enable/disable DDNS update for DHCP.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            ddns-update-override:
                                type: str
                                description: Enable/disable DDNS update override for DHCP.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            ddns-zone:
                                type: str
                                description: Zone of your domain name
                            default-gateway:
                                type: str
                                description: Default gateway IP address assigned by the DHCP server.
                            dhcp-settings-from-fortiipam:
                                type: str
                                description: Enable/disable populating of DHCP server settings from FortiIPAM.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            dns-server1:
                                type: str
                                description: DNS server 1.
                            dns-server2:
                                type: str
                                description: DNS server 2.
                            dns-server3:
                                type: str
                                description: DNS server 3.
                            dns-server4:
                                type: str
                                description: DNS server 4.
                            dns-service:
                                type: str
                                description: Options for assigning DNS servers to DHCP clients.
                                choices:
                                    - 'default'
                                    - 'specify'
                                    - 'local'
                            domain:
                                type: str
                                description: Domain name suffix for the IP addresses that the DHCP server assigns to clients.
                            enable:
                                type: str
                                description: Enable.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            exclude-range:
                                description: Exclude-Range.
                                type: list
                                elements: dict
                                suboptions:
                                    end-ip:
                                        type: str
                                        description: End of IP range.
                                    id:
                                        type: int
                                        description: ID.
                                    start-ip:
                                        type: str
                                        description: Start of IP range.
                                    vci-match:
                                        type: str
                                        description: Enable/disable vendor class identifier
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    vci-string:
                                        description: description
                                        type: str
                                    lease-time:
                                        type: int
                                        description: Lease time in seconds, 0 means default lease time.
                                    uci-match:
                                        type: str
                                        description: Enable/disable user class identifier
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    uci-string:
                                        description: description
                                        type: str
                            filename:
                                type: str
                                description: Name of the boot file on the TFTP server.
                            forticlient-on-net-status:
                                type: str
                                description: Enable/disable FortiClient-On-Net service for this DHCP server.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            id:
                                type: int
                                description: ID.
                            ip-mode:
                                type: str
                                description: Method used to assign client IP.
                                choices:
                                    - 'range'
                                    - 'usrgrp'
                            ip-range:
                                description: Ip-Range.
                                type: list
                                elements: dict
                                suboptions:
                                    end-ip:
                                        type: str
                                        description: End of IP range.
                                    id:
                                        type: int
                                        description: ID.
                                    start-ip:
                                        type: str
                                        description: Start of IP range.
                                    vci-match:
                                        type: str
                                        description: Enable/disable vendor class identifier
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    vci-string:
                                        description: description
                                        type: str
                                    lease-time:
                                        type: int
                                        description: Lease time in seconds, 0 means default lease time.
                                    uci-match:
                                        type: str
                                        description: Enable/disable user class identifier
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    uci-string:
                                        description: description
                                        type: str
                            ipsec-lease-hold:
                                type: int
                                description: DHCP over IPsec leases expire this many seconds after tunnel down
                            lease-time:
                                type: int
                                description: Lease time in seconds, 0 means unlimited.
                            mac-acl-default-action:
                                type: str
                                description: MAC access control default action
                                choices:
                                    - 'assign'
                                    - 'block'
                            netmask:
                                type: str
                                description: Netmask assigned by the DHCP server.
                            next-server:
                                type: str
                                description: IP address of a server
                            ntp-server1:
                                type: str
                                description: NTP server 1.
                            ntp-server2:
                                type: str
                                description: NTP server 2.
                            ntp-server3:
                                type: str
                                description: NTP server 3.
                            ntp-service:
                                type: str
                                description: Options for assigning Network Time Protocol
                                choices:
                                    - 'default'
                                    - 'specify'
                                    - 'local'
                            option1:
                                description: Option1.
                                type: str
                            option2:
                                description: Option2.
                                type: str
                            option3:
                                description: Option3.
                                type: str
                            option4:
                                type: str
                                description: Option4.
                            option5:
                                type: str
                                description: Option5.
                            option6:
                                type: str
                                description: Option6.
                            options:
                                description: Options.
                                type: list
                                elements: dict
                                suboptions:
                                    code:
                                        type: int
                                        description: DHCP option code.
                                    id:
                                        type: int
                                        description: ID.
                                    ip:
                                        description: DHCP option IPs.
                                        type: str
                                    type:
                                        type: str
                                        description: DHCP option type.
                                        choices:
                                            - 'hex'
                                            - 'string'
                                            - 'ip'
                                            - 'fqdn'
                                    value:
                                        type: str
                                        description: DHCP option value.
                                    vci-match:
                                        type: str
                                        description: Enable/disable vendor class identifier
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    vci-string:
                                        description: description
                                        type: str
                                    uci-match:
                                        type: str
                                        description: Enable/disable user class identifier
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    uci-string:
                                        description: description
                                        type: str
                            reserved-address:
                                description: Reserved-Address.
                                type: list
                                elements: dict
                                suboptions:
                                    action:
                                        type: str
                                        description: Options for the DHCP server to configure the client with the reserved MAC address.
                                        choices:
                                            - 'assign'
                                            - 'block'
                                            - 'reserved'
                                    circuit-id:
                                        type: str
                                        description: Option 82 circuit-ID of the client that will get the reserved IP address.
                                    circuit-id-type:
                                        type: str
                                        description: DHCP option type.
                                        choices:
                                            - 'hex'
                                            - 'string'
                                    description:
                                        type: str
                                        description: Description.
                                    id:
                                        type: int
                                        description: ID.
                                    ip:
                                        type: str
                                        description: IP address to be reserved for the MAC address.
                                    mac:
                                        type: str
                                        description: MAC address of the client that will get the reserved IP address.
                                    remote-id:
                                        type: str
                                        description: Option 82 remote-ID of the client that will get the reserved IP address.
                                    remote-id-type:
                                        type: str
                                        description: DHCP option type.
                                        choices:
                                            - 'hex'
                                            - 'string'
                                    type:
                                        type: str
                                        description: DHCP reserved-address type.
                                        choices:
                                            - 'mac'
                                            - 'option82'
                            server-type:
                                type: str
                                description: DHCP server can be a normal DHCP server or an IPsec DHCP server.
                                choices:
                                    - 'regular'
                                    - 'ipsec'
                            status:
                                type: str
                                description: Enable/disable this DHCP configuration.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            tftp-server:
                                description: One or more hostnames or IP addresses of the TFTP servers in quotes separated by spaces.
                                type: str
                            timezone:
                                type: str
                                description: Select the time zone to be assigned to DHCP clients.
                                choices:
                                    - '00'
                                    - '01'
                                    - '02'
                                    - '03'
                                    - '04'
                                    - '05'
                                    - '06'
                                    - '07'
                                    - '08'
                                    - '09'
                                    - '10'
                                    - '11'
                                    - '12'
                                    - '13'
                                    - '14'
                                    - '15'
                                    - '16'
                                    - '17'
                                    - '18'
                                    - '19'
                                    - '20'
                                    - '21'
                                    - '22'
                                    - '23'
                                    - '24'
                                    - '25'
                                    - '26'
                                    - '27'
                                    - '28'
                                    - '29'
                                    - '30'
                                    - '31'
                                    - '32'
                                    - '33'
                                    - '34'
                                    - '35'
                                    - '36'
                                    - '37'
                                    - '38'
                                    - '39'
                                    - '40'
                                    - '41'
                                    - '42'
                                    - '43'
                                    - '44'
                                    - '45'
                                    - '46'
                                    - '47'
                                    - '48'
                                    - '49'
                                    - '50'
                                    - '51'
                                    - '52'
                                    - '53'
                                    - '54'
                                    - '55'
                                    - '56'
                                    - '57'
                                    - '58'
                                    - '59'
                                    - '60'
                                    - '61'
                                    - '62'
                                    - '63'
                                    - '64'
                                    - '65'
                                    - '66'
                                    - '67'
                                    - '68'
                                    - '69'
                                    - '70'
                                    - '71'
                                    - '72'
                                    - '73'
                                    - '74'
                                    - '75'
                                    - '76'
                                    - '77'
                                    - '78'
                                    - '79'
                                    - '80'
                                    - '81'
                                    - '82'
                                    - '83'
                                    - '84'
                                    - '85'
                                    - '86'
                                    - '87'
                            timezone-option:
                                type: str
                                description: Options for the DHCP server to set the clients time zone.
                                choices:
                                    - 'disable'
                                    - 'default'
                                    - 'specify'
                            vci-match:
                                type: str
                                description: Enable/disable vendor class identifier
                                choices:
                                    - 'disable'
                                    - 'enable'
                            vci-string:
                                description: One or more VCI strings in quotes separated by spaces.
                                type: str
                            wifi-ac-service:
                                type: str
                                description: Options for assigning WiFi Access Controllers to DHCP clients
                                choices:
                                    - 'specify'
                                    - 'local'
                            wifi-ac1:
                                type: str
                                description: WiFi Access Controller 1 IP address
                            wifi-ac2:
                                type: str
                                description: WiFi Access Controller 2 IP address
                            wifi-ac3:
                                type: str
                                description: WiFi Access Controller 3 IP address
                            wins-server1:
                                type: str
                                description: WINS server 1.
                            wins-server2:
                                type: str
                                description: WINS server 2.
                            relay-agent:
                                type: str
                                description: Relay agent IP.
                            shared-subnet:
                                type: str
                                description: Enable/disable shared subnet.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    interface:
                        description: no description
                        type: dict
                        required: false
                        suboptions:
                            dhcp-relay-agent-option:
                                type: str
                                description: Dhcp-Relay-Agent-Option.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            dhcp-relay-ip:
                                description: Dhcp-Relay-Ip.
                                type: str
                            dhcp-relay-service:
                                type: str
                                description: Dhcp-Relay-Service.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            dhcp-relay-type:
                                type: str
                                description: Dhcp-Relay-Type.
                                choices:
                                    - 'regular'
                                    - 'ipsec'
                            ip:
                                type: str
                                description: Ip.
                            ipv6:
                                description: no description
                                type: dict
                                required: false
                                suboptions:
                                    autoconf:
                                        type: str
                                        description: Enable/disable address auto config.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    dhcp6-client-options:
                                        description: Dhcp6-Client-Options.
                                        type: list
                                        elements: str
                                        choices:
                                            - 'rapid'
                                            - 'iapd'
                                            - 'iana'
                                            - 'dns'
                                            - 'dnsname'
                                    dhcp6-information-request:
                                        type: str
                                        description: Enable/disable DHCPv6 information request.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    dhcp6-prefix-delegation:
                                        type: str
                                        description: Enable/disable DHCPv6 prefix delegation.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    dhcp6-prefix-hint:
                                        type: str
                                        description: DHCPv6 prefix that will be used as a hint to the upstream DHCPv6 server.
                                    dhcp6-prefix-hint-plt:
                                        type: int
                                        description: DHCPv6 prefix hint preferred life time
                                    dhcp6-prefix-hint-vlt:
                                        type: int
                                        description: DHCPv6 prefix hint valid life time
                                    dhcp6-relay-ip:
                                        type: str
                                        description: DHCPv6 relay IP address.
                                    dhcp6-relay-service:
                                        type: str
                                        description: Enable/disable DHCPv6 relay.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    dhcp6-relay-type:
                                        type: str
                                        description: DHCPv6 relay type.
                                        choices:
                                            - 'regular'
                                    icmp6-send-redirect:
                                        type: str
                                        description: Enable/disable sending of ICMPv6 redirects.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    interface-identifier:
                                        type: str
                                        description: IPv6 interface identifier.
                                    ip6-address:
                                        type: str
                                        description: Primary IPv6 address prefix, syntax
                                    ip6-allowaccess:
                                        description: Allow management access to the interface.
                                        type: list
                                        elements: str
                                        choices:
                                            - 'https'
                                            - 'ping'
                                            - 'ssh'
                                            - 'snmp'
                                            - 'http'
                                            - 'telnet'
                                            - 'fgfm'
                                            - 'capwap'
                                            - 'fabric'
                                    ip6-default-life:
                                        type: int
                                        description: Default life
                                    ip6-delegated-prefix-list:
                                        description: Ip6-Delegated-Prefix-List.
                                        type: list
                                        elements: dict
                                        suboptions:
                                            autonomous-flag:
                                                type: str
                                                description: Enable/disable the autonomous flag.
                                                choices:
                                                    - 'disable'
                                                    - 'enable'
                                            onlink-flag:
                                                type: str
                                                description: Enable/disable the onlink flag.
                                                choices:
                                                    - 'disable'
                                                    - 'enable'
                                            prefix-id:
                                                type: int
                                                description: Prefix ID.
                                            rdnss:
                                                description: Recursive DNS server option.
                                                type: str
                                            rdnss-service:
                                                type: str
                                                description: Recursive DNS service option.
                                                choices:
                                                    - 'delegated'
                                                    - 'default'
                                                    - 'specify'
                                            subnet:
                                                type: str
                                                description: Add subnet ID to routing prefix.
                                            upstream-interface:
                                                type: str
                                                description: Name of the interface that provides delegated information.
                                            delegated-prefix-iaid:
                                                type: int
                                                description: IAID of obtained delegated-prefix from the upstream interface.
                                    ip6-dns-server-override:
                                        type: str
                                        description: Enable/disable using the DNS server acquired by DHCP.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    ip6-extra-addr:
                                        description: Ip6-Extra-Addr.
                                        type: list
                                        elements: dict
                                        suboptions:
                                            prefix:
                                                type: str
                                                description: IPv6 address prefix.
                                    ip6-hop-limit:
                                        type: int
                                        description: Hop limit
                                    ip6-link-mtu:
                                        type: int
                                        description: IPv6 link MTU.
                                    ip6-manage-flag:
                                        type: str
                                        description: Enable/disable the managed flag.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    ip6-max-interval:
                                        type: int
                                        description: IPv6 maximum interval
                                    ip6-min-interval:
                                        type: int
                                        description: IPv6 minimum interval
                                    ip6-mode:
                                        type: str
                                        description: Addressing mode
                                        choices:
                                            - 'static'
                                            - 'dhcp'
                                            - 'pppoe'
                                            - 'delegated'
                                    ip6-other-flag:
                                        type: str
                                        description: Enable/disable the other IPv6 flag.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    ip6-prefix-list:
                                        description: Ip6-Prefix-List.
                                        type: list
                                        elements: dict
                                        suboptions:
                                            autonomous-flag:
                                                type: str
                                                description: Enable/disable the autonomous flag.
                                                choices:
                                                    - 'disable'
                                                    - 'enable'
                                            dnssl:
                                                description: DNS search list option.
                                                type: str
                                            onlink-flag:
                                                type: str
                                                description: Enable/disable the onlink flag.
                                                choices:
                                                    - 'disable'
                                                    - 'enable'
                                            preferred-life-time:
                                                type: int
                                                description: Preferred life time
                                            prefix:
                                                type: str
                                                description: IPv6 prefix.
                                            rdnss:
                                                description: Recursive DNS server option.
                                                type: str
                                            valid-life-time:
                                                type: int
                                                description: Valid life time
                                    ip6-reachable-time:
                                        type: int
                                        description: IPv6 reachable time
                                    ip6-retrans-time:
                                        type: int
                                        description: IPv6 retransmit time
                                    ip6-send-adv:
                                        type: str
                                        description: Enable/disable sending advertisements about the interface.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    ip6-subnet:
                                        type: str
                                        description: Subnet to routing prefix, syntax
                                    ip6-upstream-interface:
                                        type: str
                                        description: Interface name providing delegated information.
                                    nd-cert:
                                        type: str
                                        description: Neighbor discovery certificate.
                                    nd-cga-modifier:
                                        type: str
                                        description: Neighbor discovery CGA modifier.
                                    nd-mode:
                                        type: str
                                        description: Neighbor discovery mode.
                                        choices:
                                            - 'basic'
                                            - 'SEND-compatible'
                                    nd-security-level:
                                        type: int
                                        description: Neighbor discovery security level
                                    nd-timestamp-delta:
                                        type: int
                                        description: Neighbor discovery timestamp delta value
                                    nd-timestamp-fuzz:
                                        type: int
                                        description: Neighbor discovery timestamp fuzz factor
                                    unique-autoconf-addr:
                                        type: str
                                        description: Enable/disable unique auto config address.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    vrip6_link_local:
                                        type: str
                                        description: Link-local IPv6 address of virtual router.
                                    vrrp-virtual-mac6:
                                        type: str
                                        description: Enable/disable virtual MAC for VRRP.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    vrrp6:
                                        description: Vrrp6.
                                        type: list
                                        elements: dict
                                        suboptions:
                                            accept-mode:
                                                type: str
                                                description: Enable/disable accept mode.
                                                choices:
                                                    - 'disable'
                                                    - 'enable'
                                            adv-interval:
                                                type: int
                                                description: Advertisement interval
                                            preempt:
                                                type: str
                                                description: Enable/disable preempt mode.
                                                choices:
                                                    - 'disable'
                                                    - 'enable'
                                            priority:
                                                type: int
                                                description: Priority of the virtual router
                                            start-time:
                                                type: int
                                                description: Startup time
                                            status:
                                                type: str
                                                description: Enable/disable VRRP.
                                                choices:
                                                    - 'disable'
                                                    - 'enable'
                                            vrdst6:
                                                type: str
                                                description: Monitor the route to this destination.
                                            vrgrp:
                                                type: int
                                                description: VRRP group ID
                                            vrid:
                                                type: int
                                                description: Virtual router identifier
                                            vrip6:
                                                type: str
                                                description: IPv6 address of the virtual router.
                                    cli-conn6-status:
                                        type: int
                                        description: Cli-Conn6-Status.
                                    ip6-prefix-mode:
                                        type: str
                                        description: Assigning a prefix from DHCP or RA.
                                        choices:
                                            - 'dhcp6'
                                            - 'ra'
                                    ra-send-mtu:
                                        type: str
                                        description: Enable/disable sending link MTU in RA packet.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    ip6-delegated-prefix-iaid:
                                        type: int
                                        description: IAID of obtained delegated-prefix from the upstream interface.
                                    dhcp6-relay-source-interface:
                                        type: str
                                        description: Enable/disable use of address on this interface as the source address of the relay message.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                            secondary-IP:
                                type: str
                                description: Secondary-Ip.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            secondaryip:
                                description: Secondaryip.
                                type: list
                                elements: dict
                                suboptions:
                                    allowaccess:
                                        description: Management access settings for the secondary IP address.
                                        type: list
                                        elements: str
                                        choices:
                                            - 'https'
                                            - 'ping'
                                            - 'ssh'
                                            - 'snmp'
                                            - 'http'
                                            - 'telnet'
                                            - 'fgfm'
                                            - 'auto-ipsec'
                                            - 'radius-acct'
                                            - 'probe-response'
                                            - 'capwap'
                                            - 'dnp'
                                            - 'ftm'
                                            - 'fabric'
                                            - 'speed-test'
                                    detectprotocol:
                                        description: Protocols used to detect the server.
                                        type: list
                                        elements: str
                                        choices:
                                            - 'ping'
                                            - 'tcp-echo'
                                            - 'udp-echo'
                                    detectserver:
                                        type: str
                                        description: Gateways ping server for this IP.
                                    gwdetect:
                                        type: str
                                        description: Enable/disable detect gateway alive for first.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    ha-priority:
                                        type: int
                                        description: HA election priority for the PING server.
                                    id:
                                        type: int
                                        description: ID.
                                    ip:
                                        type: str
                                        description: Secondary IP address of the interface.
                                    ping-serv-status:
                                        type: int
                                        description: Ping-Serv-Status.
                                    seq:
                                        type: int
                                        description: Seq.
                                    secip-relay-ip:
                                        type: str
                                        description: DHCP relay IP address.
                            vlanid:
                                type: int
                                description: Vlanid.
                            dhcp-relay-interface-select-method:
                                type: str
                                description: no description
                                choices:
                                    - 'auto'
                                    - 'sdwan'
                                    - 'specify'
                            vrrp:
                                description: description
                                type: list
                                elements: dict
                                suboptions:
                                    accept-mode:
                                        type: str
                                        description: Enable/disable accept mode.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    adv-interval:
                                        type: int
                                        description: Advertisement interval
                                    ignore-default-route:
                                        type: str
                                        description: Enable/disable ignoring of default route when checking destination.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    preempt:
                                        type: str
                                        description: Enable/disable preempt mode.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    priority:
                                        type: int
                                        description: Priority of the virtual router
                                    proxy-arp:
                                        description: description
                                        type: list
                                        elements: dict
                                        suboptions:
                                            id:
                                                type: int
                                                description: ID.
                                            ip:
                                                type: str
                                                description: Set IP addresses of proxy ARP.
                                    start-time:
                                        type: int
                                        description: Startup time
                                    status:
                                        type: str
                                        description: Enable/disable this VRRP configuration.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    version:
                                        type: str
                                        description: VRRP version.
                                        choices:
                                            - '2'
                                            - '3'
                                    vrdst:
                                        description: description
                                        type: str
                                    vrdst-priority:
                                        type: int
                                        description: Priority of the virtual router when the virtual router destination becomes unreachable
                                    vrgrp:
                                        type: int
                                        description: VRRP group ID
                                    vrid:
                                        type: int
                                        description: Virtual router identifier
                                    vrip:
                                        type: str
                                        description: IP address of the virtual router.
            name:
                type: str
                description: Name.
            portal-message-override-group:
                type: str
                description: no description
            radius-server:
                type: str
                description: no description
            security:
                type: str
                description: no description
                choices:
                    - 'open'
                    - 'captive-portal'
                    - '8021x'
            selected-usergroups:
                type: str
                description: no description
            usergroup:
                type: str
                description: no description
            vdom:
                type: str
                description: Vdom.
            vlanid:
                type: int
                description: Vlanid.
            dhcp-server:
                description: no description
                type: dict
                required: false
                suboptions:
                    auto-configuration:
                        type: str
                        description: Enable/disable auto configuration.
                        choices:
                            - 'disable'
                            - 'enable'
                    auto-managed-status:
                        type: str
                        description: Enable/disable use of this DHCP server once this interface has been assigned an IP address from FortiIPAM.
                        choices:
                            - 'disable'
                            - 'enable'
                    conflicted-ip-timeout:
                        type: int
                        description: Time in seconds to wait after a conflicted IP address is removed from the DHCP range before it can be reused.
                    ddns-auth:
                        type: str
                        description: DDNS authentication mode.
                        choices:
                            - 'disable'
                            - 'tsig'
                    ddns-key:
                        type: str
                        description: DDNS update key
                    ddns-keyname:
                        type: str
                        description: DDNS update key name.
                    ddns-server-ip:
                        type: str
                        description: DDNS server IP.
                    ddns-ttl:
                        type: int
                        description: TTL.
                    ddns-update:
                        type: str
                        description: Enable/disable DDNS update for DHCP.
                        choices:
                            - 'disable'
                            - 'enable'
                    ddns-update-override:
                        type: str
                        description: Enable/disable DDNS update override for DHCP.
                        choices:
                            - 'disable'
                            - 'enable'
                    ddns-zone:
                        type: str
                        description: Zone of your domain name
                    default-gateway:
                        type: str
                        description: Default gateway IP address assigned by the DHCP server.
                    dhcp-settings-from-fortiipam:
                        type: str
                        description: Enable/disable populating of DHCP server settings from FortiIPAM.
                        choices:
                            - 'disable'
                            - 'enable'
                    dns-server1:
                        type: str
                        description: DNS server 1.
                    dns-server2:
                        type: str
                        description: DNS server 2.
                    dns-server3:
                        type: str
                        description: DNS server 3.
                    dns-server4:
                        type: str
                        description: DNS server 4.
                    dns-service:
                        type: str
                        description: Options for assigning DNS servers to DHCP clients.
                        choices:
                            - 'default'
                            - 'specify'
                            - 'local'
                    domain:
                        type: str
                        description: Domain name suffix for the IP addresses that the DHCP server assigns to clients.
                    enable:
                        type: str
                        description: Enable.
                        choices:
                            - 'disable'
                            - 'enable'
                    exclude-range:
                        description: Exclude-Range.
                        type: list
                        elements: dict
                        suboptions:
                            end-ip:
                                type: str
                                description: End of IP range.
                            id:
                                type: int
                                description: ID.
                            start-ip:
                                type: str
                                description: Start of IP range.
                            vci-match:
                                type: str
                                description: Enable/disable vendor class identifier
                                choices:
                                    - 'disable'
                                    - 'enable'
                            vci-string:
                                description: description
                                type: str
                            lease-time:
                                type: int
                                description: Lease time in seconds, 0 means default lease time.
                            uci-match:
                                type: str
                                description: Enable/disable user class identifier
                                choices:
                                    - 'disable'
                                    - 'enable'
                            uci-string:
                                description: description
                                type: str
                    filename:
                        type: str
                        description: Name of the boot file on the TFTP server.
                    forticlient-on-net-status:
                        type: str
                        description: Enable/disable FortiClient-On-Net service for this DHCP server.
                        choices:
                            - 'disable'
                            - 'enable'
                    id:
                        type: int
                        description: ID.
                    ip-mode:
                        type: str
                        description: Method used to assign client IP.
                        choices:
                            - 'range'
                            - 'usrgrp'
                    ip-range:
                        description: Ip-Range.
                        type: list
                        elements: dict
                        suboptions:
                            end-ip:
                                type: str
                                description: End of IP range.
                            id:
                                type: int
                                description: ID.
                            start-ip:
                                type: str
                                description: Start of IP range.
                            vci-match:
                                type: str
                                description: Enable/disable vendor class identifier
                                choices:
                                    - 'disable'
                                    - 'enable'
                            vci-string:
                                description: description
                                type: str
                            lease-time:
                                type: int
                                description: Lease time in seconds, 0 means default lease time.
                            uci-match:
                                type: str
                                description: Enable/disable user class identifier
                                choices:
                                    - 'disable'
                                    - 'enable'
                            uci-string:
                                description: description
                                type: str
                    ipsec-lease-hold:
                        type: int
                        description: DHCP over IPsec leases expire this many seconds after tunnel down
                    lease-time:
                        type: int
                        description: Lease time in seconds, 0 means unlimited.
                    mac-acl-default-action:
                        type: str
                        description: MAC access control default action
                        choices:
                            - 'assign'
                            - 'block'
                    netmask:
                        type: str
                        description: Netmask assigned by the DHCP server.
                    next-server:
                        type: str
                        description: IP address of a server
                    ntp-server1:
                        type: str
                        description: NTP server 1.
                    ntp-server2:
                        type: str
                        description: NTP server 2.
                    ntp-server3:
                        type: str
                        description: NTP server 3.
                    ntp-service:
                        type: str
                        description: Options for assigning Network Time Protocol
                        choices:
                            - 'default'
                            - 'specify'
                            - 'local'
                    option1:
                        description: Option1.
                        type: str
                    option2:
                        description: Option2.
                        type: str
                    option3:
                        description: Option3.
                        type: str
                    option4:
                        type: str
                        description: Option4.
                    option5:
                        type: str
                        description: Option5.
                    option6:
                        type: str
                        description: Option6.
                    options:
                        description: Options.
                        type: list
                        elements: dict
                        suboptions:
                            code:
                                type: int
                                description: DHCP option code.
                            id:
                                type: int
                                description: ID.
                            ip:
                                description: DHCP option IPs.
                                type: str
                            type:
                                type: str
                                description: DHCP option type.
                                choices:
                                    - 'hex'
                                    - 'string'
                                    - 'ip'
                                    - 'fqdn'
                            value:
                                type: str
                                description: DHCP option value.
                            vci-match:
                                type: str
                                description: Enable/disable vendor class identifier
                                choices:
                                    - 'disable'
                                    - 'enable'
                            vci-string:
                                description: description
                                type: str
                            uci-match:
                                type: str
                                description: Enable/disable user class identifier
                                choices:
                                    - 'disable'
                                    - 'enable'
                            uci-string:
                                description: description
                                type: str
                    reserved-address:
                        description: Reserved-Address.
                        type: list
                        elements: dict
                        suboptions:
                            action:
                                type: str
                                description: Options for the DHCP server to configure the client with the reserved MAC address.
                                choices:
                                    - 'assign'
                                    - 'block'
                                    - 'reserved'
                            circuit-id:
                                type: str
                                description: Option 82 circuit-ID of the client that will get the reserved IP address.
                            circuit-id-type:
                                type: str
                                description: DHCP option type.
                                choices:
                                    - 'hex'
                                    - 'string'
                            description:
                                type: str
                                description: Description.
                            id:
                                type: int
                                description: ID.
                            ip:
                                type: str
                                description: IP address to be reserved for the MAC address.
                            mac:
                                type: str
                                description: MAC address of the client that will get the reserved IP address.
                            remote-id:
                                type: str
                                description: Option 82 remote-ID of the client that will get the reserved IP address.
                            remote-id-type:
                                type: str
                                description: DHCP option type.
                                choices:
                                    - 'hex'
                                    - 'string'
                            type:
                                type: str
                                description: DHCP reserved-address type.
                                choices:
                                    - 'mac'
                                    - 'option82'
                    server-type:
                        type: str
                        description: DHCP server can be a normal DHCP server or an IPsec DHCP server.
                        choices:
                            - 'regular'
                            - 'ipsec'
                    status:
                        type: str
                        description: Enable/disable this DHCP configuration.
                        choices:
                            - 'disable'
                            - 'enable'
                    tftp-server:
                        description: One or more hostnames or IP addresses of the TFTP servers in quotes separated by spaces.
                        type: str
                    timezone:
                        type: str
                        description: Select the time zone to be assigned to DHCP clients.
                        choices:
                            - '00'
                            - '01'
                            - '02'
                            - '03'
                            - '04'
                            - '05'
                            - '06'
                            - '07'
                            - '08'
                            - '09'
                            - '10'
                            - '11'
                            - '12'
                            - '13'
                            - '14'
                            - '15'
                            - '16'
                            - '17'
                            - '18'
                            - '19'
                            - '20'
                            - '21'
                            - '22'
                            - '23'
                            - '24'
                            - '25'
                            - '26'
                            - '27'
                            - '28'
                            - '29'
                            - '30'
                            - '31'
                            - '32'
                            - '33'
                            - '34'
                            - '35'
                            - '36'
                            - '37'
                            - '38'
                            - '39'
                            - '40'
                            - '41'
                            - '42'
                            - '43'
                            - '44'
                            - '45'
                            - '46'
                            - '47'
                            - '48'
                            - '49'
                            - '50'
                            - '51'
                            - '52'
                            - '53'
                            - '54'
                            - '55'
                            - '56'
                            - '57'
                            - '58'
                            - '59'
                            - '60'
                            - '61'
                            - '62'
                            - '63'
                            - '64'
                            - '65'
                            - '66'
                            - '67'
                            - '68'
                            - '69'
                            - '70'
                            - '71'
                            - '72'
                            - '73'
                            - '74'
                            - '75'
                            - '76'
                            - '77'
                            - '78'
                            - '79'
                            - '80'
                            - '81'
                            - '82'
                            - '83'
                            - '84'
                            - '85'
                            - '86'
                            - '87'
                    timezone-option:
                        type: str
                        description: Options for the DHCP server to set the clients time zone.
                        choices:
                            - 'disable'
                            - 'default'
                            - 'specify'
                    vci-match:
                        type: str
                        description: Enable/disable vendor class identifier
                        choices:
                            - 'disable'
                            - 'enable'
                    vci-string:
                        description: One or more VCI strings in quotes separated by spaces.
                        type: str
                    wifi-ac-service:
                        type: str
                        description: Options for assigning WiFi Access Controllers to DHCP clients
                        choices:
                            - 'specify'
                            - 'local'
                    wifi-ac1:
                        type: str
                        description: WiFi Access Controller 1 IP address
                    wifi-ac2:
                        type: str
                        description: WiFi Access Controller 2 IP address
                    wifi-ac3:
                        type: str
                        description: WiFi Access Controller 3 IP address
                    wins-server1:
                        type: str
                        description: WINS server 1.
                    wins-server2:
                        type: str
                        description: WINS server 2.
                    relay-agent:
                        type: str
                        description: Relay agent IP.
                    shared-subnet:
                        type: str
                        description: Enable/disable shared subnet.
                        choices:
                            - 'disable'
                            - 'enable'
            interface:
                description: no description
                type: dict
                required: false
                suboptions:
                    ac-name:
                        type: str
                        description: PPPoE server name.
                    aggregate:
                        type: str
                        description: Aggregate.
                    algorithm:
                        type: str
                        description: Frame distribution algorithm.
                        choices:
                            - 'L2'
                            - 'L3'
                            - 'L4'
                            - 'LB'
                            - 'Source-MAC'
                    alias:
                        type: str
                        description: Alias will be displayed with the interface name to make it easier to distinguish.
                    allowaccess:
                        description: Permitted types of management access to this interface.
                        type: list
                        elements: str
                        choices:
                            - 'https'
                            - 'ping'
                            - 'ssh'
                            - 'snmp'
                            - 'http'
                            - 'telnet'
                            - 'fgfm'
                            - 'auto-ipsec'
                            - 'radius-acct'
                            - 'probe-response'
                            - 'capwap'
                            - 'dnp'
                            - 'ftm'
                            - 'fabric'
                            - 'speed-test'
                    ap-discover:
                        type: str
                        description: Enable/disable automatic registration of unknown FortiAP devices.
                        choices:
                            - 'disable'
                            - 'enable'
                    arpforward:
                        type: str
                        description: Enable/disable ARP forwarding.
                        choices:
                            - 'disable'
                            - 'enable'
                    atm-protocol:
                        type: str
                        description: ATM protocol.
                        choices:
                            - 'none'
                            - 'ipoa'
                    auth-type:
                        type: str
                        description: PPP authentication type to use.
                        choices:
                            - 'auto'
                            - 'pap'
                            - 'chap'
                            - 'mschapv1'
                            - 'mschapv2'
                    auto-auth-extension-device:
                        type: str
                        description: Enable/disable automatic authorization of dedicated Fortinet extension device on this interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    bandwidth-measure-time:
                        type: int
                        description: Bandwidth measure time
                    bfd:
                        type: str
                        description: Bidirectional Forwarding Detection
                        choices:
                            - 'global'
                            - 'enable'
                            - 'disable'
                    bfd-desired-min-tx:
                        type: int
                        description: BFD desired minimal transmit interval.
                    bfd-detect-mult:
                        type: int
                        description: BFD detection multiplier.
                    bfd-required-min-rx:
                        type: int
                        description: BFD required minimal receive interval.
                    broadcast-forticlient-discovery:
                        type: str
                        description: Enable/disable broadcasting FortiClient discovery messages.
                        choices:
                            - 'disable'
                            - 'enable'
                    broadcast-forward:
                        type: str
                        description: Enable/disable broadcast forwarding.
                        choices:
                            - 'disable'
                            - 'enable'
                    captive-portal:
                        type: int
                        description: Enable/disable captive portal.
                    cli-conn-status:
                        type: int
                        description: Cli-Conn-Status.
                    color:
                        type: int
                        description: Color of icon on the GUI.
                    ddns:
                        type: str
                        description: Ddns.
                        choices:
                            - 'disable'
                            - 'enable'
                    ddns-auth:
                        type: str
                        description: Ddns-Auth.
                        choices:
                            - 'disable'
                            - 'tsig'
                    ddns-domain:
                        type: str
                        description: Ddns-Domain.
                    ddns-key:
                        type: str
                        description: Ddns-Key.
                    ddns-keyname:
                        type: str
                        description: Ddns-Keyname.
                    ddns-password:
                        description: Ddns-Password.
                        type: str
                    ddns-server:
                        type: str
                        description: Ddns-Server.
                        choices:
                            - 'dhs.org'
                            - 'dyndns.org'
                            - 'dyns.net'
                            - 'tzo.com'
                            - 'ods.org'
                            - 'vavic.com'
                            - 'now.net.cn'
                            - 'dipdns.net'
                            - 'easydns.com'
                            - 'genericDDNS'
                    ddns-server-ip:
                        type: str
                        description: Ddns-Server-Ip.
                    ddns-sn:
                        type: str
                        description: Ddns-Sn.
                    ddns-ttl:
                        type: int
                        description: Ddns-Ttl.
                    ddns-username:
                        type: str
                        description: Ddns-Username.
                    ddns-zone:
                        type: str
                        description: Ddns-Zone.
                    dedicated-to:
                        type: str
                        description: Configure interface for single purpose.
                        choices:
                            - 'none'
                            - 'management'
                    defaultgw:
                        type: str
                        description: Enable to get the gateway IP from the DHCP or PPPoE server.
                        choices:
                            - 'disable'
                            - 'enable'
                    description:
                        type: str
                        description: Description.
                    detected-peer-mtu:
                        type: int
                        description: Detected-Peer-Mtu.
                    detectprotocol:
                        description: Protocols used to detect the server.
                        type: list
                        elements: str
                        choices:
                            - 'ping'
                            - 'tcp-echo'
                            - 'udp-echo'
                    detectserver:
                        type: str
                        description: Gateways ping server for this IP.
                    device-access-list:
                        type: str
                        description: Device access list.
                    device-identification:
                        type: str
                        description: Enable/disable passively gathering of device identity information about the devices on the network connected to this in...
                        choices:
                            - 'disable'
                            - 'enable'
                    device-identification-active-scan:
                        type: str
                        description: Enable/disable active gathering of device identity information about the devices on the network connected to this inter...
                        choices:
                            - 'disable'
                            - 'enable'
                    device-netscan:
                        type: str
                        description: Enable/disable inclusion of devices detected on this interface in network vulnerability scans.
                        choices:
                            - 'disable'
                            - 'enable'
                    device-user-identification:
                        type: str
                        description: Enable/disable passive gathering of user identity information about users on this interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    devindex:
                        type: int
                        description: Devindex.
                    dhcp-client-identifier:
                        type: str
                        description: DHCP client identifier.
                    dhcp-relay-agent-option:
                        type: str
                        description: Enable/disable DHCP relay agent option.
                        choices:
                            - 'disable'
                            - 'enable'
                    dhcp-relay-interface:
                        type: str
                        description: Specify outgoing interface to reach server.
                    dhcp-relay-interface-select-method:
                        type: str
                        description: Specify how to select outgoing interface to reach server.
                        choices:
                            - 'auto'
                            - 'sdwan'
                            - 'specify'
                    dhcp-relay-ip:
                        description: DHCP relay IP address.
                        type: str
                    dhcp-relay-service:
                        type: str
                        description: Enable/disable allowing this interface to act as a DHCP relay.
                        choices:
                            - 'disable'
                            - 'enable'
                    dhcp-relay-type:
                        type: str
                        description: DHCP relay type
                        choices:
                            - 'regular'
                            - 'ipsec'
                    dhcp-renew-time:
                        type: int
                        description: DHCP renew time in seconds
                    disc-retry-timeout:
                        type: int
                        description: Time in seconds to wait before retrying to start a PPPoE discovery, 0 means no timeout.
                    disconnect-threshold:
                        type: int
                        description: Time in milliseconds to wait before sending a notification that this interface is down or disconnected.
                    distance:
                        type: int
                        description: Distance for routes learned through PPPoE or DHCP, lower distance indicates preferred route.
                    dns-query:
                        type: str
                        description: Dns-Query.
                        choices:
                            - 'disable'
                            - 'recursive'
                            - 'non-recursive'
                    dns-server-override:
                        type: str
                        description: Enable/disable use DNS acquired by DHCP or PPPoE.
                        choices:
                            - 'disable'
                            - 'enable'
                    drop-fragment:
                        type: str
                        description: Enable/disable drop fragment packets.
                        choices:
                            - 'disable'
                            - 'enable'
                    drop-overlapped-fragment:
                        type: str
                        description: Enable/disable drop overlapped fragment packets.
                        choices:
                            - 'disable'
                            - 'enable'
                    egress-cos:
                        type: str
                        description: Override outgoing CoS in user VLAN tag.
                        choices:
                            - 'disable'
                            - 'cos0'
                            - 'cos1'
                            - 'cos2'
                            - 'cos3'
                            - 'cos4'
                            - 'cos5'
                            - 'cos6'
                            - 'cos7'
                    egress-shaping-profile:
                        type: str
                        description: Outgoing traffic shaping profile.
                    eip:
                        type: str
                        description: Eip.
                    endpoint-compliance:
                        type: str
                        description: Enable/disable endpoint compliance enforcement.
                        choices:
                            - 'disable'
                            - 'enable'
                    estimated-downstream-bandwidth:
                        type: int
                        description: Estimated maximum downstream bandwidth
                    estimated-upstream-bandwidth:
                        type: int
                        description: Estimated maximum upstream bandwidth
                    explicit-ftp-proxy:
                        type: str
                        description: Enable/disable the explicit FTP proxy on this interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    explicit-web-proxy:
                        type: str
                        description: Enable/disable the explicit web proxy on this interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    external:
                        type: str
                        description: Enable/disable identifying the interface as an external interface
                        choices:
                            - 'disable'
                            - 'enable'
                    fail-action-on-extender:
                        type: str
                        description: Action on extender when interface fail .
                        choices:
                            - 'soft-restart'
                            - 'hard-restart'
                            - 'reboot'
                    fail-alert-interfaces:
                        type: str
                        description: Names of the FortiGate interfaces to which the link failure alert is sent.
                    fail-alert-method:
                        type: str
                        description: Select link-failed-signal or link-down method to alert about a failed link.
                        choices:
                            - 'link-failed-signal'
                            - 'link-down'
                    fail-detect:
                        type: str
                        description: Enable/disable fail detection features for this interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    fail-detect-option:
                        description: Options for detecting that this interface has failed.
                        type: list
                        elements: str
                        choices:
                            - 'detectserver'
                            - 'link-down'
                    fdp:
                        type: str
                        description: Fdp.
                        choices:
                            - 'disable'
                            - 'enable'
                    fortiheartbeat:
                        type: str
                        description: Enable/disable FortiHeartBeat
                        choices:
                            - 'disable'
                            - 'enable'
                    fortilink:
                        type: str
                        description: Enable FortiLink to dedicate this interface to manage other Fortinet devices.
                        choices:
                            - 'disable'
                            - 'enable'
                    fortilink-backup-link:
                        type: int
                        description: Fortilink-Backup-Link.
                    fortilink-neighbor-detect:
                        type: str
                        description: Protocol for FortiGate neighbor discovery.
                        choices:
                            - 'lldp'
                            - 'fortilink'
                    fortilink-split-interface:
                        type: str
                        description: Enable/disable FortiLink split interface to connect member link to different FortiSwitch in stack for uplink redundancy.
                        choices:
                            - 'disable'
                            - 'enable'
                    fortilink-stacking:
                        type: str
                        description: Enable/disable FortiLink switch-stacking on this interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    forward-domain:
                        type: int
                        description: Transparent mode forward domain.
                    forward-error-correction:
                        type: str
                        description: Enable/disable forward error correction
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'rs-fec'
                            - 'base-r-fec'
                            - 'fec-cl91'
                            - 'fec-cl74'
                            - 'rs-544'
                            - 'none'
                            - 'cl91-rs-fec'
                            - 'cl74-fc-fec'
                    fp-anomaly:
                        description: Fp-Anomaly.
                        type: list
                        elements: str
                        choices:
                            - 'drop_tcp_fin_noack'
                            - 'pass_winnuke'
                            - 'pass_tcpland'
                            - 'pass_udpland'
                            - 'pass_icmpland'
                            - 'pass_ipland'
                            - 'pass_iprr'
                            - 'pass_ipssrr'
                            - 'pass_iplsrr'
                            - 'pass_ipstream'
                            - 'pass_ipsecurity'
                            - 'pass_iptimestamp'
                            - 'pass_ipunknown_option'
                            - 'pass_ipunknown_prot'
                            - 'pass_icmp_frag'
                            - 'pass_tcp_no_flag'
                            - 'pass_tcp_fin_noack'
                            - 'drop_winnuke'
                            - 'drop_tcpland'
                            - 'drop_udpland'
                            - 'drop_icmpland'
                            - 'drop_ipland'
                            - 'drop_iprr'
                            - 'drop_ipssrr'
                            - 'drop_iplsrr'
                            - 'drop_ipstream'
                            - 'drop_ipsecurity'
                            - 'drop_iptimestamp'
                            - 'drop_ipunknown_option'
                            - 'drop_ipunknown_prot'
                            - 'drop_icmp_frag'
                            - 'drop_tcp_no_flag'
                    fp-disable:
                        description: Fp-Disable.
                        type: list
                        elements: str
                        choices:
                            - 'all'
                            - 'ipsec'
                            - 'none'
                    gateway-address:
                        type: str
                        description: Gateway address
                    gi-gk:
                        type: str
                        description: Enable/disable Gi Gatekeeper.
                        choices:
                            - 'disable'
                            - 'enable'
                    gwaddr:
                        type: str
                        description: Gateway address
                    gwdetect:
                        type: str
                        description: Enable/disable detect gateway alive for first.
                        choices:
                            - 'disable'
                            - 'enable'
                    ha-priority:
                        type: int
                        description: HA election priority for the PING server.
                    icmp-accept-redirect:
                        type: str
                        description: Enable/disable ICMP accept redirect.
                        choices:
                            - 'disable'
                            - 'enable'
                    icmp-redirect:
                        type: str
                        description: Enable/disable ICMP redirect.
                        choices:
                            - 'disable'
                            - 'enable'
                    icmp-send-redirect:
                        type: str
                        description: Enable/disable sending of ICMP redirects.
                        choices:
                            - 'disable'
                            - 'enable'
                    ident-accept:
                        type: str
                        description: Enable/disable authentication for this interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    idle-timeout:
                        type: int
                        description: PPPoE auto disconnect after idle timeout seconds, 0 means no timeout.
                    if-mdix:
                        type: str
                        description: Interface MDIX mode
                        choices:
                            - 'auto'
                            - 'normal'
                            - 'crossover'
                    if-media:
                        type: str
                        description: Select interface media type
                        choices:
                            - 'auto'
                            - 'copper'
                            - 'fiber'
                    in-force-vlan-cos:
                        type: int
                        description: In-Force-Vlan-Cos.
                    inbandwidth:
                        type: int
                        description: Bandwidth limit for incoming traffic
                    ingress-cos:
                        type: str
                        description: Override incoming CoS in user VLAN tag on VLAN interface or assign a priority VLAN tag on physical interface.
                        choices:
                            - 'disable'
                            - 'cos0'
                            - 'cos1'
                            - 'cos2'
                            - 'cos3'
                            - 'cos4'
                            - 'cos5'
                            - 'cos6'
                            - 'cos7'
                    ingress-shaping-profile:
                        type: str
                        description: Incoming traffic shaping profile.
                    ingress-spillover-threshold:
                        type: int
                        description: Ingress Spillover threshold
                    internal:
                        type: int
                        description: Implicitly created.
                    ip:
                        type: str
                        description: Interface IPv4 address and subnet mask, syntax
                    ip-managed-by-fortiipam:
                        type: str
                        description: Enable/disable automatic IP address assignment of this interface by FortiIPAM.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'inherit-global'
                    ipmac:
                        type: str
                        description: Enable/disable IP/MAC binding.
                        choices:
                            - 'disable'
                            - 'enable'
                    ips-sniffer-mode:
                        type: str
                        description: Enable/disable the use of this interface as a one-armed sniffer.
                        choices:
                            - 'disable'
                            - 'enable'
                    ipunnumbered:
                        type: str
                        description: Unnumbered IP used for PPPoE interfaces for which no unique local address is provided.
                    ipv6:
                        description: no description
                        type: dict
                        required: false
                        suboptions:
                            autoconf:
                                type: str
                                description: Enable/disable address auto config.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            dhcp6-client-options:
                                description: Dhcp6-Client-Options.
                                type: list
                                elements: str
                                choices:
                                    - 'rapid'
                                    - 'iapd'
                                    - 'iana'
                                    - 'dns'
                                    - 'dnsname'
                            dhcp6-information-request:
                                type: str
                                description: Enable/disable DHCPv6 information request.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            dhcp6-prefix-delegation:
                                type: str
                                description: Enable/disable DHCPv6 prefix delegation.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            dhcp6-prefix-hint:
                                type: str
                                description: DHCPv6 prefix that will be used as a hint to the upstream DHCPv6 server.
                            dhcp6-prefix-hint-plt:
                                type: int
                                description: DHCPv6 prefix hint preferred life time
                            dhcp6-prefix-hint-vlt:
                                type: int
                                description: DHCPv6 prefix hint valid life time
                            dhcp6-relay-ip:
                                type: str
                                description: DHCPv6 relay IP address.
                            dhcp6-relay-service:
                                type: str
                                description: Enable/disable DHCPv6 relay.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            dhcp6-relay-type:
                                type: str
                                description: DHCPv6 relay type.
                                choices:
                                    - 'regular'
                            icmp6-send-redirect:
                                type: str
                                description: Enable/disable sending of ICMPv6 redirects.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            interface-identifier:
                                type: str
                                description: IPv6 interface identifier.
                            ip6-address:
                                type: str
                                description: Primary IPv6 address prefix, syntax
                            ip6-allowaccess:
                                description: Allow management access to the interface.
                                type: list
                                elements: str
                                choices:
                                    - 'https'
                                    - 'ping'
                                    - 'ssh'
                                    - 'snmp'
                                    - 'http'
                                    - 'telnet'
                                    - 'fgfm'
                                    - 'capwap'
                                    - 'fabric'
                            ip6-default-life:
                                type: int
                                description: Default life
                            ip6-delegated-prefix-list:
                                description: Ip6-Delegated-Prefix-List.
                                type: list
                                elements: dict
                                suboptions:
                                    autonomous-flag:
                                        type: str
                                        description: Enable/disable the autonomous flag.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    onlink-flag:
                                        type: str
                                        description: Enable/disable the onlink flag.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    prefix-id:
                                        type: int
                                        description: Prefix ID.
                                    rdnss:
                                        description: Recursive DNS server option.
                                        type: str
                                    rdnss-service:
                                        type: str
                                        description: Recursive DNS service option.
                                        choices:
                                            - 'delegated'
                                            - 'default'
                                            - 'specify'
                                    subnet:
                                        type: str
                                        description: Add subnet ID to routing prefix.
                                    upstream-interface:
                                        type: str
                                        description: Name of the interface that provides delegated information.
                                    delegated-prefix-iaid:
                                        type: int
                                        description: IAID of obtained delegated-prefix from the upstream interface.
                            ip6-dns-server-override:
                                type: str
                                description: Enable/disable using the DNS server acquired by DHCP.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            ip6-extra-addr:
                                description: Ip6-Extra-Addr.
                                type: list
                                elements: dict
                                suboptions:
                                    prefix:
                                        type: str
                                        description: IPv6 address prefix.
                            ip6-hop-limit:
                                type: int
                                description: Hop limit
                            ip6-link-mtu:
                                type: int
                                description: IPv6 link MTU.
                            ip6-manage-flag:
                                type: str
                                description: Enable/disable the managed flag.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            ip6-max-interval:
                                type: int
                                description: IPv6 maximum interval
                            ip6-min-interval:
                                type: int
                                description: IPv6 minimum interval
                            ip6-mode:
                                type: str
                                description: Addressing mode
                                choices:
                                    - 'static'
                                    - 'dhcp'
                                    - 'pppoe'
                                    - 'delegated'
                            ip6-other-flag:
                                type: str
                                description: Enable/disable the other IPv6 flag.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            ip6-prefix-list:
                                description: Ip6-Prefix-List.
                                type: list
                                elements: dict
                                suboptions:
                                    autonomous-flag:
                                        type: str
                                        description: Enable/disable the autonomous flag.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    dnssl:
                                        description: DNS search list option.
                                        type: str
                                    onlink-flag:
                                        type: str
                                        description: Enable/disable the onlink flag.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    preferred-life-time:
                                        type: int
                                        description: Preferred life time
                                    prefix:
                                        type: str
                                        description: IPv6 prefix.
                                    rdnss:
                                        description: Recursive DNS server option.
                                        type: str
                                    valid-life-time:
                                        type: int
                                        description: Valid life time
                            ip6-reachable-time:
                                type: int
                                description: IPv6 reachable time
                            ip6-retrans-time:
                                type: int
                                description: IPv6 retransmit time
                            ip6-send-adv:
                                type: str
                                description: Enable/disable sending advertisements about the interface.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            ip6-subnet:
                                type: str
                                description: Subnet to routing prefix, syntax
                            ip6-upstream-interface:
                                type: str
                                description: Interface name providing delegated information.
                            nd-cert:
                                type: str
                                description: Neighbor discovery certificate.
                            nd-cga-modifier:
                                type: str
                                description: Neighbor discovery CGA modifier.
                            nd-mode:
                                type: str
                                description: Neighbor discovery mode.
                                choices:
                                    - 'basic'
                                    - 'SEND-compatible'
                            nd-security-level:
                                type: int
                                description: Neighbor discovery security level
                            nd-timestamp-delta:
                                type: int
                                description: Neighbor discovery timestamp delta value
                            nd-timestamp-fuzz:
                                type: int
                                description: Neighbor discovery timestamp fuzz factor
                            unique-autoconf-addr:
                                type: str
                                description: Enable/disable unique auto config address.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            vrip6_link_local:
                                type: str
                                description: Link-local IPv6 address of virtual router.
                            vrrp-virtual-mac6:
                                type: str
                                description: Enable/disable virtual MAC for VRRP.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            vrrp6:
                                description: Vrrp6.
                                type: list
                                elements: dict
                                suboptions:
                                    accept-mode:
                                        type: str
                                        description: Enable/disable accept mode.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    adv-interval:
                                        type: int
                                        description: Advertisement interval
                                    preempt:
                                        type: str
                                        description: Enable/disable preempt mode.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    priority:
                                        type: int
                                        description: Priority of the virtual router
                                    start-time:
                                        type: int
                                        description: Startup time
                                    status:
                                        type: str
                                        description: Enable/disable VRRP.
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    vrdst6:
                                        type: str
                                        description: Monitor the route to this destination.
                                    vrgrp:
                                        type: int
                                        description: VRRP group ID
                                    vrid:
                                        type: int
                                        description: Virtual router identifier
                                    vrip6:
                                        type: str
                                        description: IPv6 address of the virtual router.
                            cli-conn6-status:
                                type: int
                                description: Cli-Conn6-Status.
                            ip6-prefix-mode:
                                type: str
                                description: Assigning a prefix from DHCP or RA.
                                choices:
                                    - 'dhcp6'
                                    - 'ra'
                            ra-send-mtu:
                                type: str
                                description: Enable/disable sending link MTU in RA packet.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            ip6-delegated-prefix-iaid:
                                type: int
                                description: IAID of obtained delegated-prefix from the upstream interface.
                            dhcp6-relay-source-interface:
                                type: str
                                description: Enable/disable use of address on this interface as the source address of the relay message.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    l2forward:
                        type: str
                        description: Enable/disable l2 forwarding.
                        choices:
                            - 'disable'
                            - 'enable'
                    l2tp-client:
                        type: str
                        description: Enable/disable this interface as a Layer 2 Tunnelling Protocol
                        choices:
                            - 'disable'
                            - 'enable'
                    lacp-ha-slave:
                        type: str
                        description: LACP HA slave.
                        choices:
                            - 'disable'
                            - 'enable'
                    lacp-mode:
                        type: str
                        description: LACP mode.
                        choices:
                            - 'static'
                            - 'passive'
                            - 'active'
                    lacp-speed:
                        type: str
                        description: How often the interface sends LACP messages.
                        choices:
                            - 'slow'
                            - 'fast'
                    lcp-echo-interval:
                        type: int
                        description: Time in seconds between PPPoE Link Control Protocol
                    lcp-max-echo-fails:
                        type: int
                        description: Maximum missed LCP echo messages before disconnect.
                    link-up-delay:
                        type: int
                        description: Number of milliseconds to wait before considering a link is up.
                    listen-forticlient-connection:
                        type: str
                        description: Listen-Forticlient-Connection.
                        choices:
                            - 'disable'
                            - 'enable'
                    lldp-network-policy:
                        type: str
                        description: LLDP-MED network policy profile.
                    lldp-reception:
                        type: str
                        description: Enable/disable Link Layer Discovery Protocol
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'vdom'
                    lldp-transmission:
                        type: str
                        description: Enable/disable Link Layer Discovery Protocol
                        choices:
                            - 'enable'
                            - 'disable'
                            - 'vdom'
                    log:
                        type: str
                        description: Log.
                        choices:
                            - 'disable'
                            - 'enable'
                    macaddr:
                        type: str
                        description: Change the interfaces MAC address.
                    managed-subnetwork-size:
                        type: str
                        description: Number of IP addresses to be allocated by FortiIPAM and used by this FortiGate units DHCP server settings.
                        choices:
                            - '256'
                            - '512'
                            - '1024'
                            - '2048'
                            - '4096'
                            - '8192'
                            - '16384'
                            - '32768'
                            - '65536'
                            - '32'
                            - '64'
                            - '128'
                    management-ip:
                        type: str
                        description: High Availability in-band management IP address of this interface.
                    max-egress-burst-rate:
                        type: int
                        description: Max egress burst rate
                    max-egress-rate:
                        type: int
                        description: Max egress rate
                    measured-downstream-bandwidth:
                        type: int
                        description: Measured downstream bandwidth
                    measured-upstream-bandwidth:
                        type: int
                        description: Measured upstream bandwidth
                    mediatype:
                        type: str
                        description: Select SFP media interface type
                        choices:
                            - 'serdes-sfp'
                            - 'sgmii-sfp'
                            - 'cfp2-sr10'
                            - 'cfp2-lr4'
                            - 'serdes-copper-sfp'
                            - 'sr'
                            - 'cr'
                            - 'lr'
                            - 'qsfp28-sr4'
                            - 'qsfp28-lr4'
                            - 'qsfp28-cr4'
                            - 'sr4'
                            - 'cr4'
                            - 'lr4'
                            - 'none'
                            - 'gmii'
                            - 'sgmii'
                            - 'sr2'
                            - 'lr2'
                            - 'cr2'
                            - 'sr8'
                            - 'lr8'
                            - 'cr8'
                    member:
                        type: str
                        description: Physical interfaces that belong to the aggregate or redundant interface.
                    min-links:
                        type: int
                        description: Minimum number of aggregated ports that must be up.
                    min-links-down:
                        type: str
                        description: Action to take when less than the configured minimum number of links are active.
                        choices:
                            - 'operational'
                            - 'administrative'
                    mode:
                        type: str
                        description: Addressing mode
                        choices:
                            - 'static'
                            - 'dhcp'
                            - 'pppoe'
                            - 'pppoa'
                            - 'ipoa'
                            - 'eoa'
                    monitor-bandwidth:
                        type: str
                        description: Enable monitoring bandwidth on this interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    mtu:
                        type: int
                        description: MTU value for this interface.
                    mtu-override:
                        type: str
                        description: Enable to set a custom MTU for this interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    mux-type:
                        type: str
                        description: Multiplexer type
                        choices:
                            - 'llc-encaps'
                            - 'vc-encaps'
                    name:
                        type: str
                        description: Name.
                    ndiscforward:
                        type: str
                        description: Enable/disable NDISC forwarding.
                        choices:
                            - 'disable'
                            - 'enable'
                    netbios-forward:
                        type: str
                        description: Enable/disable NETBIOS forwarding.
                        choices:
                            - 'disable'
                            - 'enable'
                    netflow-sampler:
                        type: str
                        description: Enable/disable NetFlow on this interface and set the data that NetFlow collects
                        choices:
                            - 'disable'
                            - 'tx'
                            - 'rx'
                            - 'both'
                    np-qos-profile:
                        type: int
                        description: NP QoS profile ID.
                    npu-fastpath:
                        type: str
                        description: Npu-Fastpath.
                        choices:
                            - 'disable'
                            - 'enable'
                    nst:
                        type: str
                        description: Nst.
                        choices:
                            - 'disable'
                            - 'enable'
                    out-force-vlan-cos:
                        type: int
                        description: Out-Force-Vlan-Cos.
                    outbandwidth:
                        type: int
                        description: Bandwidth limit for outgoing traffic
                    padt-retry-timeout:
                        type: int
                        description: PPPoE Active Discovery Terminate
                    password:
                        description: PPPoE accounts password.
                        type: str
                    peer-interface:
                        type: str
                        description: Peer-Interface.
                    phy-mode:
                        type: str
                        description: DSL physical mode.
                        choices:
                            - 'auto'
                            - 'adsl'
                            - 'vdsl'
                            - 'adsl-auto'
                            - 'vdsl2'
                            - 'adsl2+'
                            - 'adsl2'
                            - 'g.dmt'
                            - 't1.413'
                            - 'g.lite'
                    ping-serv-status:
                        type: int
                        description: Ping-Serv-Status.
                    poe:
                        type: str
                        description: Enable/disable PoE status.
                        choices:
                            - 'disable'
                            - 'enable'
                    polling-interval:
                        type: int
                        description: sFlow polling interval
                    pppoe-unnumbered-negotiate:
                        type: str
                        description: Enable/disable PPPoE unnumbered negotiation.
                        choices:
                            - 'disable'
                            - 'enable'
                    pptp-auth-type:
                        type: str
                        description: PPTP authentication type.
                        choices:
                            - 'auto'
                            - 'pap'
                            - 'chap'
                            - 'mschapv1'
                            - 'mschapv2'
                    pptp-client:
                        type: str
                        description: Enable/disable PPTP client.
                        choices:
                            - 'disable'
                            - 'enable'
                    pptp-password:
                        description: PPTP password.
                        type: str
                    pptp-server-ip:
                        type: str
                        description: PPTP server IP address.
                    pptp-timeout:
                        type: int
                        description: Idle timer in minutes
                    pptp-user:
                        type: str
                        description: PPTP user name.
                    preserve-session-route:
                        type: str
                        description: Enable/disable preservation of session route when dirty.
                        choices:
                            - 'disable'
                            - 'enable'
                    priority:
                        type: int
                        description: Priority of learned routes.
                    priority-override:
                        type: str
                        description: Enable/disable fail back to higher priority port once recovered.
                        choices:
                            - 'disable'
                            - 'enable'
                    proxy-captive-portal:
                        type: str
                        description: Enable/disable proxy captive portal on this interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    redundant-interface:
                        type: str
                        description: Redundant-Interface.
                    remote-ip:
                        type: str
                        description: Remote IP address of tunnel.
                    replacemsg-override-group:
                        type: str
                        description: Replacement message override group.
                    retransmission:
                        type: str
                        description: Enable/disable DSL retransmission.
                        choices:
                            - 'disable'
                            - 'enable'
                    ring-rx:
                        type: int
                        description: RX ring size.
                    ring-tx:
                        type: int
                        description: TX ring size.
                    role:
                        type: str
                        description: Interface role.
                        choices:
                            - 'lan'
                            - 'wan'
                            - 'dmz'
                            - 'undefined'
                    sample-direction:
                        type: str
                        description: Data that NetFlow collects
                        choices:
                            - 'rx'
                            - 'tx'
                            - 'both'
                    sample-rate:
                        type: int
                        description: sFlow sample rate
                    scan-botnet-connections:
                        type: str
                        description: Enable monitoring or blocking connections to Botnet servers through this interface.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    secondary-IP:
                        type: str
                        description: Enable/disable adding a secondary IP to this interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    secondaryip:
                        description: Secondaryip.
                        type: list
                        elements: dict
                        suboptions:
                            allowaccess:
                                description: Management access settings for the secondary IP address.
                                type: list
                                elements: str
                                choices:
                                    - 'https'
                                    - 'ping'
                                    - 'ssh'
                                    - 'snmp'
                                    - 'http'
                                    - 'telnet'
                                    - 'fgfm'
                                    - 'auto-ipsec'
                                    - 'radius-acct'
                                    - 'probe-response'
                                    - 'capwap'
                                    - 'dnp'
                                    - 'ftm'
                                    - 'fabric'
                                    - 'speed-test'
                            detectprotocol:
                                description: Protocols used to detect the server.
                                type: list
                                elements: str
                                choices:
                                    - 'ping'
                                    - 'tcp-echo'
                                    - 'udp-echo'
                            detectserver:
                                type: str
                                description: Gateways ping server for this IP.
                            gwdetect:
                                type: str
                                description: Enable/disable detect gateway alive for first.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            ha-priority:
                                type: int
                                description: HA election priority for the PING server.
                            id:
                                type: int
                                description: ID.
                            ip:
                                type: str
                                description: Secondary IP address of the interface.
                            ping-serv-status:
                                type: int
                                description: Ping-Serv-Status.
                            seq:
                                type: int
                                description: Seq.
                            secip-relay-ip:
                                type: str
                                description: DHCP relay IP address.
                    security-8021x-dynamic-vlan-id:
                        type: int
                        description: VLAN ID for virtual switch.
                    security-8021x-master:
                        type: str
                        description: '802.'
                    security-8021x-mode:
                        type: str
                        description: '802.'
                        choices:
                            - 'default'
                            - 'dynamic-vlan'
                            - 'fallback'
                            - 'slave'
                    security-exempt-list:
                        type: str
                        description: Name of security-exempt-list.
                    security-external-logout:
                        type: str
                        description: URL of external authentication logout server.
                    security-external-web:
                        type: str
                        description: URL of external authentication web server.
                    security-groups:
                        type: str
                        description: User groups that can authenticate with the captive portal.
                    security-mac-auth-bypass:
                        type: str
                        description: Enable/disable MAC authentication bypass.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'mac-auth-only'
                    security-mode:
                        type: str
                        description: Turn on captive portal authentication for this interface.
                        choices:
                            - 'none'
                            - 'captive-portal'
                            - '802.1X'
                    security-redirect-url:
                        type: str
                        description: URL redirection after disclaimer/authentication.
                    service-name:
                        type: str
                        description: PPPoE service name.
                    sflow-sampler:
                        type: str
                        description: Enable/disable sFlow on this interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    speed:
                        type: str
                        description: Interface speed.
                        choices:
                            - 'auto'
                            - '10full'
                            - '10half'
                            - '100full'
                            - '100half'
                            - '1000full'
                            - '1000half'
                            - '10000full'
                            - '1000auto'
                            - '10000auto'
                            - '40000full'
                            - '100Gfull'
                            - '25000full'
                            - '40000auto'
                            - '25000auto'
                            - '100Gauto'
                            - '400Gfull'
                            - '400Gauto'
                            - '50000full'
                            - '2500auto'
                            - '5000auto'
                            - '50000auto'
                            - '200Gfull'
                            - '200Gauto'
                            - '100auto'
                    spillover-threshold:
                        type: int
                        description: Egress Spillover threshold
                    src-check:
                        type: str
                        description: Enable/disable source IP check.
                        choices:
                            - 'disable'
                            - 'enable'
                    status:
                        type: str
                        description: Bring the interface up or shut the interface down.
                        choices:
                            - 'down'
                            - 'up'
                    stp:
                        type: str
                        description: Enable/disable STP.
                        choices:
                            - 'disable'
                            - 'enable'
                    stp-ha-slave:
                        type: str
                        description: Control STP behaviour on HA slave.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'priority-adjust'
                    stpforward:
                        type: str
                        description: Enable/disable STP forwarding.
                        choices:
                            - 'disable'
                            - 'enable'
                    stpforward-mode:
                        type: str
                        description: Configure STP forwarding mode.
                        choices:
                            - 'rpl-all-ext-id'
                            - 'rpl-bridge-ext-id'
                            - 'rpl-nothing'
                    strip-priority-vlan-tag:
                        type: str
                        description: Strip-Priority-Vlan-Tag.
                        choices:
                            - 'disable'
                            - 'enable'
                    subst:
                        type: str
                        description: Enable to always send packets from this interface to a destination MAC address.
                        choices:
                            - 'disable'
                            - 'enable'
                    substitute-dst-mac:
                        type: str
                        description: Destination MAC address that all packets are sent to from this interface.
                    swc-first-create:
                        type: int
                        description: Initial create for switch-controller VLANs.
                    swc-vlan:
                        type: int
                        description: Swc-Vlan.
                    switch:
                        type: str
                        description: Switch.
                    switch-controller-access-vlan:
                        type: str
                        description: Block FortiSwitch port-to-port traffic.
                        choices:
                            - 'disable'
                            - 'enable'
                    switch-controller-arp-inspection:
                        type: str
                        description: Enable/disable FortiSwitch ARP inspection.
                        choices:
                            - 'disable'
                            - 'enable'
                    switch-controller-auth:
                        type: str
                        description: Switch controller authentication.
                        choices:
                            - 'radius'
                            - 'usergroup'
                    switch-controller-dhcp-snooping:
                        type: str
                        description: Switch controller DHCP snooping.
                        choices:
                            - 'disable'
                            - 'enable'
                    switch-controller-dhcp-snooping-option82:
                        type: str
                        description: Switch controller DHCP snooping option82.
                        choices:
                            - 'disable'
                            - 'enable'
                    switch-controller-dhcp-snooping-verify-mac:
                        type: str
                        description: Switch controller DHCP snooping verify MAC.
                        choices:
                            - 'disable'
                            - 'enable'
                    switch-controller-feature:
                        type: str
                        description: Interfaces purpose when assigning traffic
                        choices:
                            - 'none'
                            - 'default-vlan'
                            - 'quarantine'
                            - 'sniffer'
                            - 'voice'
                            - 'camera'
                            - 'rspan'
                            - 'video'
                            - 'nac'
                            - 'nac-segment'
                    switch-controller-igmp-snooping:
                        type: str
                        description: Switch controller IGMP snooping.
                        choices:
                            - 'disable'
                            - 'enable'
                    switch-controller-igmp-snooping-fast-leave:
                        type: str
                        description: Switch controller IGMP snooping fast-leave.
                        choices:
                            - 'disable'
                            - 'enable'
                    switch-controller-igmp-snooping-proxy:
                        type: str
                        description: Switch controller IGMP snooping proxy.
                        choices:
                            - 'disable'
                            - 'enable'
                    switch-controller-iot-scanning:
                        type: str
                        description: Enable/disable managed FortiSwitch IoT scanning.
                        choices:
                            - 'disable'
                            - 'enable'
                    switch-controller-learning-limit:
                        type: int
                        description: Limit the number of dynamic MAC addresses on this VLAN
                    switch-controller-mgmt-vlan:
                        type: int
                        description: VLAN to use for FortiLink management purposes.
                    switch-controller-nac:
                        type: str
                        description: Integrated NAC settings for managed FortiSwitch.
                    switch-controller-radius-server:
                        type: str
                        description: RADIUS server name for this FortiSwitch VLAN.
                    switch-controller-rspan-mode:
                        type: str
                        description: Stop Layer2 MAC learning and interception of BPDUs and other packets on this interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    switch-controller-source-ip:
                        type: str
                        description: Source IP address used in FortiLink over L3 connections.
                        choices:
                            - 'outbound'
                            - 'fixed'
                    switch-controller-traffic-policy:
                        type: str
                        description: Switch controller traffic policy for the VLAN.
                    tc-mode:
                        type: str
                        description: DSL transfer mode.
                        choices:
                            - 'ptm'
                            - 'atm'
                    tcp-mss:
                        type: int
                        description: TCP maximum segment size.
                    trunk:
                        type: str
                        description: Enable/disable VLAN trunk.
                        choices:
                            - 'disable'
                            - 'enable'
                    trust-ip-1:
                        type: str
                        description: Trusted host for dedicated management traffic
                    trust-ip-2:
                        type: str
                        description: Trusted host for dedicated management traffic
                    trust-ip-3:
                        type: str
                        description: Trusted host for dedicated management traffic
                    trust-ip6-1:
                        type: str
                        description: Trusted IPv6 host for dedicated management traffic
                    trust-ip6-2:
                        type: str
                        description: Trusted IPv6 host for dedicated management traffic
                    trust-ip6-3:
                        type: str
                        description: Trusted IPv6 host for dedicated management traffic
                    type:
                        type: str
                        description: Interface type.
                        choices:
                            - 'physical'
                            - 'vlan'
                            - 'aggregate'
                            - 'redundant'
                            - 'tunnel'
                            - 'wireless'
                            - 'vdom-link'
                            - 'loopback'
                            - 'switch'
                            - 'hard-switch'
                            - 'hdlc'
                            - 'vap-switch'
                            - 'wl-mesh'
                            - 'fortilink'
                            - 'switch-vlan'
                            - 'fctrl-trunk'
                            - 'tdm'
                            - 'fext-wan'
                            - 'vxlan'
                            - 'emac-vlan'
                            - 'geneve'
                            - 'ssl'
                            - 'lan-extension'
                    username:
                        type: str
                        description: Username of the PPPoE account, provided by your ISP.
                    vci:
                        type: int
                        description: Virtual Channel ID
                    vectoring:
                        type: str
                        description: Enable/disable DSL vectoring.
                        choices:
                            - 'disable'
                            - 'enable'
                    vindex:
                        type: int
                        description: Vindex.
                    vlan-protocol:
                        type: str
                        description: Ethernet protocol of VLAN.
                        choices:
                            - '8021q'
                            - '8021ad'
                    vlanforward:
                        type: str
                        description: Enable/disable traffic forwarding between VLANs on this interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    vlanid:
                        type: int
                        description: VLAN ID
                    vpi:
                        type: int
                        description: Virtual Path ID
                    vrf:
                        type: int
                        description: Virtual Routing Forwarding ID.
                    vrrp:
                        description: Vrrp.
                        type: list
                        elements: dict
                        suboptions:
                            accept-mode:
                                type: str
                                description: Enable/disable accept mode.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            adv-interval:
                                type: int
                                description: Advertisement interval
                            ignore-default-route:
                                type: str
                                description: Enable/disable ignoring of default route when checking destination.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            preempt:
                                type: str
                                description: Enable/disable preempt mode.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            priority:
                                type: int
                                description: Priority of the virtual router
                            start-time:
                                type: int
                                description: Startup time
                            status:
                                type: str
                                description: Enable/disable this VRRP configuration.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            version:
                                type: str
                                description: VRRP version.
                                choices:
                                    - '2'
                                    - '3'
                            vrdst:
                                description: Monitor the route to this destination.
                                type: str
                            vrdst-priority:
                                type: int
                                description: Priority of the virtual router when the virtual router destination becomes unreachable
                            vrgrp:
                                type: int
                                description: VRRP group ID
                            vrid:
                                type: int
                                description: Virtual router identifier
                            vrip:
                                type: str
                                description: IP address of the virtual router.
                            proxy-arp:
                                description: description
                                type: list
                                elements: dict
                                suboptions:
                                    id:
                                        type: int
                                        description: ID.
                                    ip:
                                        type: str
                                        description: Set IP addresses of proxy ARP.
                    vrrp-virtual-mac:
                        type: str
                        description: Enable/disable use of virtual MAC for VRRP.
                        choices:
                            - 'disable'
                            - 'enable'
                    wccp:
                        type: str
                        description: Enable/disable WCCP on this interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    weight:
                        type: int
                        description: Default weight for static routes
                    wifi-5g-threshold:
                        type: str
                        description: Minimal signal strength to be considered as a good 5G AP.
                    wifi-acl:
                        type: str
                        description: Access control for MAC addresses in the MAC list.
                        choices:
                            - 'deny'
                            - 'allow'
                    wifi-ap-band:
                        type: str
                        description: How to select the AP to connect.
                        choices:
                            - 'any'
                            - '5g-preferred'
                            - '5g-only'
                    wifi-auth:
                        type: str
                        description: WiFi authentication.
                        choices:
                            - 'PSK'
                            - 'RADIUS'
                            - 'radius'
                            - 'usergroup'
                    wifi-auto-connect:
                        type: str
                        description: Enable/disable WiFi network auto connect.
                        choices:
                            - 'disable'
                            - 'enable'
                    wifi-auto-save:
                        type: str
                        description: Enable/disable WiFi network automatic save.
                        choices:
                            - 'disable'
                            - 'enable'
                    wifi-broadcast-ssid:
                        type: str
                        description: Enable/disable SSID broadcast in the beacon.
                        choices:
                            - 'disable'
                            - 'enable'
                    wifi-encrypt:
                        type: str
                        description: Data encryption.
                        choices:
                            - 'TKIP'
                            - 'AES'
                    wifi-fragment-threshold:
                        type: int
                        description: WiFi fragment threshold
                    wifi-key:
                        description: WiFi WEP Key.
                        type: str
                    wifi-keyindex:
                        type: int
                        description: WEP key index
                    wifi-mac-filter:
                        type: str
                        description: Enable/disable MAC filter status.
                        choices:
                            - 'disable'
                            - 'enable'
                    wifi-passphrase:
                        description: WiFi pre-shared key for WPA.
                        type: str
                    wifi-radius-server:
                        type: str
                        description: WiFi RADIUS server for WPA.
                    wifi-rts-threshold:
                        type: int
                        description: WiFi RTS threshold
                    wifi-security:
                        type: str
                        description: Wireless access security of SSID.
                        choices:
                            - 'None'
                            - 'WEP64'
                            - 'wep64'
                            - 'WEP128'
                            - 'wep128'
                            - 'WPA_PSK'
                            - 'WPA_RADIUS'
                            - 'WPA'
                            - 'WPA2'
                            - 'WPA2_AUTO'
                            - 'open'
                            - 'wpa-personal'
                            - 'wpa-enterprise'
                            - 'wpa-only-personal'
                            - 'wpa-only-enterprise'
                            - 'wpa2-only-personal'
                            - 'wpa2-only-enterprise'
                    wifi-ssid:
                        type: str
                        description: IEEE 802.
                    wifi-usergroup:
                        type: str
                        description: WiFi user group for WPA.
                    wins-ip:
                        type: str
                        description: WINS server IP.
                    dhcp-relay-request-all-server:
                        type: str
                        description: Enable/disable sending of DHCP requests to all servers.
                        choices:
                            - 'disable'
                            - 'enable'
                    stp-ha-secondary:
                        type: str
                        description: Control STP behaviour on HA secondary.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'priority-adjust'
                    switch-controller-dynamic:
                        type: str
                        description: Integrated FortiLink settings for managed FortiSwitch.
                    auth-cert:
                        type: str
                        description: HTTPS server certificate.
                    auth-portal-addr:
                        type: str
                        description: Address of captive portal.
                    dhcp-classless-route-addition:
                        type: str
                        description: Enable/disable addition of classless static routes retrieved from DHCP server.
                        choices:
                            - 'disable'
                            - 'enable'
                    dhcp-relay-link-selection:
                        type: str
                        description: DHCP relay link selection.
                    dns-server-protocol:
                        description: description
                        type: list
                        elements: str
                        choices:
                            - 'cleartext'
                            - 'dot'
                            - 'doh'
                    eap-ca-cert:
                        type: str
                        description: EAP CA certificate name.
                    eap-identity:
                        type: str
                        description: EAP identity.
                    eap-method:
                        type: str
                        description: EAP method.
                        choices:
                            - 'tls'
                            - 'peap'
                    eap-password:
                        description: description
                        type: str
                    eap-supplicant:
                        type: str
                        description: Enable/disable EAP-Supplicant.
                        choices:
                            - 'disable'
                            - 'enable'
                    eap-user-cert:
                        type: str
                        description: EAP user certificate name.
                    ike-saml-server:
                        type: str
                        description: Configure IKE authentication SAML server.
                    lacp-ha-secondary:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    pvc-atm-qos:
                        type: str
                        description: SFP-DSL ADSL Fallback PVC ATM QoS.
                        choices:
                            - 'cbr'
                            - 'rt-vbr'
                            - 'nrt-vbr'
                    pvc-chan:
                        type: int
                        description: SFP-DSL ADSL Fallback PVC Channel.
                    pvc-crc:
                        type: int
                        description: SFP-DSL ADSL Fallback PVC CRC Option
                    pvc-pcr:
                        type: int
                        description: SFP-DSL ADSL Fallback PVC Packet Cell Rate in cells
                    pvc-scr:
                        type: int
                        description: SFP-DSL ADSL Fallback PVC Sustainable Cell Rate in cells
                    pvc-vlan-id:
                        type: int
                        description: SFP-DSL ADSL Fallback PVC VLAN ID.
                    pvc-vlan-rx-id:
                        type: int
                        description: SFP-DSL ADSL Fallback PVC VLANID RX.
                    pvc-vlan-rx-op:
                        type: str
                        description: SFP-DSL ADSL Fallback PVC VLAN RX op.
                        choices:
                            - 'pass-through'
                            - 'replace'
                            - 'remove'
                    pvc-vlan-tx-id:
                        type: int
                        description: SFP-DSL ADSL Fallback PVC VLAN ID TX.
                    pvc-vlan-tx-op:
                        type: str
                        description: SFP-DSL ADSL Fallback PVC VLAN TX op.
                        choices:
                            - 'pass-through'
                            - 'replace'
                            - 'remove'
                    reachable-time:
                        type: int
                        description: IPv4 reachable time in milliseconds
                    select-profile-30a-35b:
                        type: str
                        description: Select VDSL Profile 30a or 35b.
                        choices:
                            - '30A'
                            - '35B'
                    sfp-dsl:
                        type: str
                        description: Enable/disable SFP DSL.
                        choices:
                            - 'disable'
                            - 'enable'
                    sfp-dsl-adsl-fallback:
                        type: str
                        description: Enable/disable SFP DSL ADSL fallback.
                        choices:
                            - 'disable'
                            - 'enable'
                    sfp-dsl-autodetect:
                        type: str
                        description: Enable/disable SFP DSL MAC address autodetect.
                        choices:
                            - 'disable'
                            - 'enable'
                    sfp-dsl-mac:
                        type: str
                        description: SFP DSL MAC address.
                    sw-algorithm:
                        type: str
                        description: Frame distribution algorithm for switch.
                        choices:
                            - 'l2'
                            - 'l3'
                            - 'eh'
                    system-id:
                        type: str
                        description: Define a system ID for the aggregate interface.
                    system-id-type:
                        type: str
                        description: Method in which system ID is generated.
                        choices:
                            - 'auto'
                            - 'user'
                    vlan-id:
                        type: int
                        description: Vlan ID
                    vlan-op-mode:
                        type: str
                        description: Configure DSL 802.
                        choices:
                            - 'tag'
                            - 'untag'
                            - 'passthrough'
                    generic-receive-offload:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    interconnect-profile:
                        type: str
                        description: Set interconnect profile.
                        choices:
                            - 'default'
                            - 'profile1'
                            - 'profile2'
                    large-receive-offload:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    aggregate-type:
                        type: str
                        description: Type of aggregation.
                        choices:
                            - 'physical'
                            - 'vxlan'
                    switch-controller-netflow-collect:
                        type: str
                        description: NetFlow collection and processing.
                        choices:
                            - 'disable'
                            - 'enable'
                    wifi-dns-server1:
                        type: str
                        description: DNS server 1.
                    wifi-dns-server2:
                        type: str
                        description: DNS server 2.
                    wifi-gateway:
                        type: str
                        description: IPv4 default gateway IP address.
                    default-purdue-level:
                        type: str
                        description: default purdue level of device detected on this interface.
                        choices:
                            - '1'
                            - '2'
                            - '3'
                            - '4'
                            - '5'
                            - '1.5'
                            - '2.5'
                            - '3.5'
                            - '5.5'
                    dhcp-broadcast-flag:
                        type: str
                        description: Enable/disable setting of the broadcast flag in messages sent by the DHCP client
                        choices:
                            - 'disable'
                            - 'enable'
                    dhcp-smart-relay:
                        type: str
                        description: Enable/disable DHCP smart relay.
                        choices:
                            - 'disable'
                            - 'enable'
                    switch-controller-offloading:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    switch-controller-offloading-gw:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    switch-controller-offloading-ip:
                        type: str
                        description: no description

'''

EXAMPLES = '''
 - hosts: fortimanager-inventory
   collections:
     - fortinet.fortimanager
   connection: httpapi
   vars:
      ansible_httpapi_use_ssl: True
      ansible_httpapi_validate_certs: False
      ansible_httpapi_port: 443
   tasks:
    - name: no description
      fmgr_fsp_vlan:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         state: <value in [present, absent]>
         fsp_vlan:
            _dhcp-status: <value in [disable, enable]>
            auth: <value in [radius, usergroup]>
            color: <value of integer>
            comments: <value of string>
            dynamic_mapping:
              -
                  _dhcp-status: <value in [disable, enable]>
                  _scope:
                    -
                        name: <value of string>
                        vdom: <value of string>
                  dhcp-server:
                     auto-configuration: <value in [disable, enable]>
                     auto-managed-status: <value in [disable, enable]>
                     conflicted-ip-timeout: <value of integer>
                     ddns-auth: <value in [disable, tsig]>
                     ddns-key: <value of string>
                     ddns-keyname: <value of string>
                     ddns-server-ip: <value of string>
                     ddns-ttl: <value of integer>
                     ddns-update: <value in [disable, enable]>
                     ddns-update-override: <value in [disable, enable]>
                     ddns-zone: <value of string>
                     default-gateway: <value of string>
                     dhcp-settings-from-fortiipam: <value in [disable, enable]>
                     dns-server1: <value of string>
                     dns-server2: <value of string>
                     dns-server3: <value of string>
                     dns-server4: <value of string>
                     dns-service: <value in [default, specify, local]>
                     domain: <value of string>
                     enable: <value in [disable, enable]>
                     exclude-range:
                       -
                           end-ip: <value of string>
                           id: <value of integer>
                           start-ip: <value of string>
                           vci-match: <value in [disable, enable]>
                           vci-string: <value of string>
                           lease-time: <value of integer>
                           uci-match: <value in [disable, enable]>
                           uci-string: <value of string>
                     filename: <value of string>
                     forticlient-on-net-status: <value in [disable, enable]>
                     id: <value of integer>
                     ip-mode: <value in [range, usrgrp]>
                     ip-range:
                       -
                           end-ip: <value of string>
                           id: <value of integer>
                           start-ip: <value of string>
                           vci-match: <value in [disable, enable]>
                           vci-string: <value of string>
                           lease-time: <value of integer>
                           uci-match: <value in [disable, enable]>
                           uci-string: <value of string>
                     ipsec-lease-hold: <value of integer>
                     lease-time: <value of integer>
                     mac-acl-default-action: <value in [assign, block]>
                     netmask: <value of string>
                     next-server: <value of string>
                     ntp-server1: <value of string>
                     ntp-server2: <value of string>
                     ntp-server3: <value of string>
                     ntp-service: <value in [default, specify, local]>
                     option1: <value of string>
                     option2: <value of string>
                     option3: <value of string>
                     option4: <value of string>
                     option5: <value of string>
                     option6: <value of string>
                     options:
                       -
                           code: <value of integer>
                           id: <value of integer>
                           ip: <value of string>
                           type: <value in [hex, string, ip, ...]>
                           value: <value of string>
                           vci-match: <value in [disable, enable]>
                           vci-string: <value of string>
                           uci-match: <value in [disable, enable]>
                           uci-string: <value of string>
                     reserved-address:
                       -
                           action: <value in [assign, block, reserved]>
                           circuit-id: <value of string>
                           circuit-id-type: <value in [hex, string]>
                           description: <value of string>
                           id: <value of integer>
                           ip: <value of string>
                           mac: <value of string>
                           remote-id: <value of string>
                           remote-id-type: <value in [hex, string]>
                           type: <value in [mac, option82]>
                     server-type: <value in [regular, ipsec]>
                     status: <value in [disable, enable]>
                     tftp-server: <value of string>
                     timezone: <value in [00, 01, 02, ...]>
                     timezone-option: <value in [disable, default, specify]>
                     vci-match: <value in [disable, enable]>
                     vci-string: <value of string>
                     wifi-ac-service: <value in [specify, local]>
                     wifi-ac1: <value of string>
                     wifi-ac2: <value of string>
                     wifi-ac3: <value of string>
                     wins-server1: <value of string>
                     wins-server2: <value of string>
                     relay-agent: <value of string>
                     shared-subnet: <value in [disable, enable]>
                  interface:
                     dhcp-relay-agent-option: <value in [disable, enable]>
                     dhcp-relay-ip: <value of string>
                     dhcp-relay-service: <value in [disable, enable]>
                     dhcp-relay-type: <value in [regular, ipsec]>
                     ip: <value of string>
                     ipv6:
                        autoconf: <value in [disable, enable]>
                        dhcp6-client-options:
                          - rapid
                          - iapd
                          - iana
                          - dns
                          - dnsname
                        dhcp6-information-request: <value in [disable, enable]>
                        dhcp6-prefix-delegation: <value in [disable, enable]>
                        dhcp6-prefix-hint: <value of string>
                        dhcp6-prefix-hint-plt: <value of integer>
                        dhcp6-prefix-hint-vlt: <value of integer>
                        dhcp6-relay-ip: <value of string>
                        dhcp6-relay-service: <value in [disable, enable]>
                        dhcp6-relay-type: <value in [regular]>
                        icmp6-send-redirect: <value in [disable, enable]>
                        interface-identifier: <value of string>
                        ip6-address: <value of string>
                        ip6-allowaccess:
                          - https
                          - ping
                          - ssh
                          - snmp
                          - http
                          - telnet
                          - fgfm
                          - capwap
                          - fabric
                        ip6-default-life: <value of integer>
                        ip6-delegated-prefix-list:
                          -
                              autonomous-flag: <value in [disable, enable]>
                              onlink-flag: <value in [disable, enable]>
                              prefix-id: <value of integer>
                              rdnss: <value of string>
                              rdnss-service: <value in [delegated, default, specify]>
                              subnet: <value of string>
                              upstream-interface: <value of string>
                              delegated-prefix-iaid: <value of integer>
                        ip6-dns-server-override: <value in [disable, enable]>
                        ip6-extra-addr:
                          -
                              prefix: <value of string>
                        ip6-hop-limit: <value of integer>
                        ip6-link-mtu: <value of integer>
                        ip6-manage-flag: <value in [disable, enable]>
                        ip6-max-interval: <value of integer>
                        ip6-min-interval: <value of integer>
                        ip6-mode: <value in [static, dhcp, pppoe, ...]>
                        ip6-other-flag: <value in [disable, enable]>
                        ip6-prefix-list:
                          -
                              autonomous-flag: <value in [disable, enable]>
                              dnssl: <value of string>
                              onlink-flag: <value in [disable, enable]>
                              preferred-life-time: <value of integer>
                              prefix: <value of string>
                              rdnss: <value of string>
                              valid-life-time: <value of integer>
                        ip6-reachable-time: <value of integer>
                        ip6-retrans-time: <value of integer>
                        ip6-send-adv: <value in [disable, enable]>
                        ip6-subnet: <value of string>
                        ip6-upstream-interface: <value of string>
                        nd-cert: <value of string>
                        nd-cga-modifier: <value of string>
                        nd-mode: <value in [basic, SEND-compatible]>
                        nd-security-level: <value of integer>
                        nd-timestamp-delta: <value of integer>
                        nd-timestamp-fuzz: <value of integer>
                        unique-autoconf-addr: <value in [disable, enable]>
                        vrip6_link_local: <value of string>
                        vrrp-virtual-mac6: <value in [disable, enable]>
                        vrrp6:
                          -
                              accept-mode: <value in [disable, enable]>
                              adv-interval: <value of integer>
                              preempt: <value in [disable, enable]>
                              priority: <value of integer>
                              start-time: <value of integer>
                              status: <value in [disable, enable]>
                              vrdst6: <value of string>
                              vrgrp: <value of integer>
                              vrid: <value of integer>
                              vrip6: <value of string>
                        cli-conn6-status: <value of integer>
                        ip6-prefix-mode: <value in [dhcp6, ra]>
                        ra-send-mtu: <value in [disable, enable]>
                        ip6-delegated-prefix-iaid: <value of integer>
                        dhcp6-relay-source-interface: <value in [disable, enable]>
                     secondary-IP: <value in [disable, enable]>
                     secondaryip:
                       -
                           allowaccess:
                             - https
                             - ping
                             - ssh
                             - snmp
                             - http
                             - telnet
                             - fgfm
                             - auto-ipsec
                             - radius-acct
                             - probe-response
                             - capwap
                             - dnp
                             - ftm
                             - fabric
                             - speed-test
                           detectprotocol:
                             - ping
                             - tcp-echo
                             - udp-echo
                           detectserver: <value of string>
                           gwdetect: <value in [disable, enable]>
                           ha-priority: <value of integer>
                           id: <value of integer>
                           ip: <value of string>
                           ping-serv-status: <value of integer>
                           seq: <value of integer>
                           secip-relay-ip: <value of string>
                     vlanid: <value of integer>
                     dhcp-relay-interface-select-method: <value in [auto, sdwan, specify]>
                     vrrp:
                       -
                           accept-mode: <value in [disable, enable]>
                           adv-interval: <value of integer>
                           ignore-default-route: <value in [disable, enable]>
                           preempt: <value in [disable, enable]>
                           priority: <value of integer>
                           proxy-arp:
                             -
                                 id: <value of integer>
                                 ip: <value of string>
                           start-time: <value of integer>
                           status: <value in [disable, enable]>
                           version: <value in [2, 3]>
                           vrdst: <value of string>
                           vrdst-priority: <value of integer>
                           vrgrp: <value of integer>
                           vrid: <value of integer>
                           vrip: <value of string>
            name: <value of string>
            portal-message-override-group: <value of string>
            radius-server: <value of string>
            security: <value in [open, captive-portal, 8021x]>
            selected-usergroups: <value of string>
            usergroup: <value of string>
            vdom: <value of string>
            vlanid: <value of integer>
            dhcp-server:
               auto-configuration: <value in [disable, enable]>
               auto-managed-status: <value in [disable, enable]>
               conflicted-ip-timeout: <value of integer>
               ddns-auth: <value in [disable, tsig]>
               ddns-key: <value of string>
               ddns-keyname: <value of string>
               ddns-server-ip: <value of string>
               ddns-ttl: <value of integer>
               ddns-update: <value in [disable, enable]>
               ddns-update-override: <value in [disable, enable]>
               ddns-zone: <value of string>
               default-gateway: <value of string>
               dhcp-settings-from-fortiipam: <value in [disable, enable]>
               dns-server1: <value of string>
               dns-server2: <value of string>
               dns-server3: <value of string>
               dns-server4: <value of string>
               dns-service: <value in [default, specify, local]>
               domain: <value of string>
               enable: <value in [disable, enable]>
               exclude-range:
                 -
                     end-ip: <value of string>
                     id: <value of integer>
                     start-ip: <value of string>
                     vci-match: <value in [disable, enable]>
                     vci-string: <value of string>
                     lease-time: <value of integer>
                     uci-match: <value in [disable, enable]>
                     uci-string: <value of string>
               filename: <value of string>
               forticlient-on-net-status: <value in [disable, enable]>
               id: <value of integer>
               ip-mode: <value in [range, usrgrp]>
               ip-range:
                 -
                     end-ip: <value of string>
                     id: <value of integer>
                     start-ip: <value of string>
                     vci-match: <value in [disable, enable]>
                     vci-string: <value of string>
                     lease-time: <value of integer>
                     uci-match: <value in [disable, enable]>
                     uci-string: <value of string>
               ipsec-lease-hold: <value of integer>
               lease-time: <value of integer>
               mac-acl-default-action: <value in [assign, block]>
               netmask: <value of string>
               next-server: <value of string>
               ntp-server1: <value of string>
               ntp-server2: <value of string>
               ntp-server3: <value of string>
               ntp-service: <value in [default, specify, local]>
               option1: <value of string>
               option2: <value of string>
               option3: <value of string>
               option4: <value of string>
               option5: <value of string>
               option6: <value of string>
               options:
                 -
                     code: <value of integer>
                     id: <value of integer>
                     ip: <value of string>
                     type: <value in [hex, string, ip, ...]>
                     value: <value of string>
                     vci-match: <value in [disable, enable]>
                     vci-string: <value of string>
                     uci-match: <value in [disable, enable]>
                     uci-string: <value of string>
               reserved-address:
                 -
                     action: <value in [assign, block, reserved]>
                     circuit-id: <value of string>
                     circuit-id-type: <value in [hex, string]>
                     description: <value of string>
                     id: <value of integer>
                     ip: <value of string>
                     mac: <value of string>
                     remote-id: <value of string>
                     remote-id-type: <value in [hex, string]>
                     type: <value in [mac, option82]>
               server-type: <value in [regular, ipsec]>
               status: <value in [disable, enable]>
               tftp-server: <value of string>
               timezone: <value in [00, 01, 02, ...]>
               timezone-option: <value in [disable, default, specify]>
               vci-match: <value in [disable, enable]>
               vci-string: <value of string>
               wifi-ac-service: <value in [specify, local]>
               wifi-ac1: <value of string>
               wifi-ac2: <value of string>
               wifi-ac3: <value of string>
               wins-server1: <value of string>
               wins-server2: <value of string>
               relay-agent: <value of string>
               shared-subnet: <value in [disable, enable]>
            interface:
               ac-name: <value of string>
               aggregate: <value of string>
               algorithm: <value in [L2, L3, L4, ...]>
               alias: <value of string>
               allowaccess:
                 - https
                 - ping
                 - ssh
                 - snmp
                 - http
                 - telnet
                 - fgfm
                 - auto-ipsec
                 - radius-acct
                 - probe-response
                 - capwap
                 - dnp
                 - ftm
                 - fabric
                 - speed-test
               ap-discover: <value in [disable, enable]>
               arpforward: <value in [disable, enable]>
               atm-protocol: <value in [none, ipoa]>
               auth-type: <value in [auto, pap, chap, ...]>
               auto-auth-extension-device: <value in [disable, enable]>
               bandwidth-measure-time: <value of integer>
               bfd: <value in [global, enable, disable]>
               bfd-desired-min-tx: <value of integer>
               bfd-detect-mult: <value of integer>
               bfd-required-min-rx: <value of integer>
               broadcast-forticlient-discovery: <value in [disable, enable]>
               broadcast-forward: <value in [disable, enable]>
               captive-portal: <value of integer>
               cli-conn-status: <value of integer>
               color: <value of integer>
               ddns: <value in [disable, enable]>
               ddns-auth: <value in [disable, tsig]>
               ddns-domain: <value of string>
               ddns-key: <value of string>
               ddns-keyname: <value of string>
               ddns-password: <value of string>
               ddns-server: <value in [dhs.org, dyndns.org, dyns.net, ...]>
               ddns-server-ip: <value of string>
               ddns-sn: <value of string>
               ddns-ttl: <value of integer>
               ddns-username: <value of string>
               ddns-zone: <value of string>
               dedicated-to: <value in [none, management]>
               defaultgw: <value in [disable, enable]>
               description: <value of string>
               detected-peer-mtu: <value of integer>
               detectprotocol:
                 - ping
                 - tcp-echo
                 - udp-echo
               detectserver: <value of string>
               device-access-list: <value of string>
               device-identification: <value in [disable, enable]>
               device-identification-active-scan: <value in [disable, enable]>
               device-netscan: <value in [disable, enable]>
               device-user-identification: <value in [disable, enable]>
               devindex: <value of integer>
               dhcp-client-identifier: <value of string>
               dhcp-relay-agent-option: <value in [disable, enable]>
               dhcp-relay-interface: <value of string>
               dhcp-relay-interface-select-method: <value in [auto, sdwan, specify]>
               dhcp-relay-ip: <value of string>
               dhcp-relay-service: <value in [disable, enable]>
               dhcp-relay-type: <value in [regular, ipsec]>
               dhcp-renew-time: <value of integer>
               disc-retry-timeout: <value of integer>
               disconnect-threshold: <value of integer>
               distance: <value of integer>
               dns-query: <value in [disable, recursive, non-recursive]>
               dns-server-override: <value in [disable, enable]>
               drop-fragment: <value in [disable, enable]>
               drop-overlapped-fragment: <value in [disable, enable]>
               egress-cos: <value in [disable, cos0, cos1, ...]>
               egress-shaping-profile: <value of string>
               eip: <value of string>
               endpoint-compliance: <value in [disable, enable]>
               estimated-downstream-bandwidth: <value of integer>
               estimated-upstream-bandwidth: <value of integer>
               explicit-ftp-proxy: <value in [disable, enable]>
               explicit-web-proxy: <value in [disable, enable]>
               external: <value in [disable, enable]>
               fail-action-on-extender: <value in [soft-restart, hard-restart, reboot]>
               fail-alert-interfaces: <value of string>
               fail-alert-method: <value in [link-failed-signal, link-down]>
               fail-detect: <value in [disable, enable]>
               fail-detect-option:
                 - detectserver
                 - link-down
               fdp: <value in [disable, enable]>
               fortiheartbeat: <value in [disable, enable]>
               fortilink: <value in [disable, enable]>
               fortilink-backup-link: <value of integer>
               fortilink-neighbor-detect: <value in [lldp, fortilink]>
               fortilink-split-interface: <value in [disable, enable]>
               fortilink-stacking: <value in [disable, enable]>
               forward-domain: <value of integer>
               forward-error-correction: <value in [disable, enable, rs-fec, ...]>
               fp-anomaly:
                 - drop_tcp_fin_noack
                 - pass_winnuke
                 - pass_tcpland
                 - pass_udpland
                 - pass_icmpland
                 - pass_ipland
                 - pass_iprr
                 - pass_ipssrr
                 - pass_iplsrr
                 - pass_ipstream
                 - pass_ipsecurity
                 - pass_iptimestamp
                 - pass_ipunknown_option
                 - pass_ipunknown_prot
                 - pass_icmp_frag
                 - pass_tcp_no_flag
                 - pass_tcp_fin_noack
                 - drop_winnuke
                 - drop_tcpland
                 - drop_udpland
                 - drop_icmpland
                 - drop_ipland
                 - drop_iprr
                 - drop_ipssrr
                 - drop_iplsrr
                 - drop_ipstream
                 - drop_ipsecurity
                 - drop_iptimestamp
                 - drop_ipunknown_option
                 - drop_ipunknown_prot
                 - drop_icmp_frag
                 - drop_tcp_no_flag
               fp-disable:
                 - all
                 - ipsec
                 - none
               gateway-address: <value of string>
               gi-gk: <value in [disable, enable]>
               gwaddr: <value of string>
               gwdetect: <value in [disable, enable]>
               ha-priority: <value of integer>
               icmp-accept-redirect: <value in [disable, enable]>
               icmp-redirect: <value in [disable, enable]>
               icmp-send-redirect: <value in [disable, enable]>
               ident-accept: <value in [disable, enable]>
               idle-timeout: <value of integer>
               if-mdix: <value in [auto, normal, crossover]>
               if-media: <value in [auto, copper, fiber]>
               in-force-vlan-cos: <value of integer>
               inbandwidth: <value of integer>
               ingress-cos: <value in [disable, cos0, cos1, ...]>
               ingress-shaping-profile: <value of string>
               ingress-spillover-threshold: <value of integer>
               internal: <value of integer>
               ip: <value of string>
               ip-managed-by-fortiipam: <value in [disable, enable, inherit-global]>
               ipmac: <value in [disable, enable]>
               ips-sniffer-mode: <value in [disable, enable]>
               ipunnumbered: <value of string>
               ipv6:
                  autoconf: <value in [disable, enable]>
                  dhcp6-client-options:
                    - rapid
                    - iapd
                    - iana
                    - dns
                    - dnsname
                  dhcp6-information-request: <value in [disable, enable]>
                  dhcp6-prefix-delegation: <value in [disable, enable]>
                  dhcp6-prefix-hint: <value of string>
                  dhcp6-prefix-hint-plt: <value of integer>
                  dhcp6-prefix-hint-vlt: <value of integer>
                  dhcp6-relay-ip: <value of string>
                  dhcp6-relay-service: <value in [disable, enable]>
                  dhcp6-relay-type: <value in [regular]>
                  icmp6-send-redirect: <value in [disable, enable]>
                  interface-identifier: <value of string>
                  ip6-address: <value of string>
                  ip6-allowaccess:
                    - https
                    - ping
                    - ssh
                    - snmp
                    - http
                    - telnet
                    - fgfm
                    - capwap
                    - fabric
                  ip6-default-life: <value of integer>
                  ip6-delegated-prefix-list:
                    -
                        autonomous-flag: <value in [disable, enable]>
                        onlink-flag: <value in [disable, enable]>
                        prefix-id: <value of integer>
                        rdnss: <value of string>
                        rdnss-service: <value in [delegated, default, specify]>
                        subnet: <value of string>
                        upstream-interface: <value of string>
                        delegated-prefix-iaid: <value of integer>
                  ip6-dns-server-override: <value in [disable, enable]>
                  ip6-extra-addr:
                    -
                        prefix: <value of string>
                  ip6-hop-limit: <value of integer>
                  ip6-link-mtu: <value of integer>
                  ip6-manage-flag: <value in [disable, enable]>
                  ip6-max-interval: <value of integer>
                  ip6-min-interval: <value of integer>
                  ip6-mode: <value in [static, dhcp, pppoe, ...]>
                  ip6-other-flag: <value in [disable, enable]>
                  ip6-prefix-list:
                    -
                        autonomous-flag: <value in [disable, enable]>
                        dnssl: <value of string>
                        onlink-flag: <value in [disable, enable]>
                        preferred-life-time: <value of integer>
                        prefix: <value of string>
                        rdnss: <value of string>
                        valid-life-time: <value of integer>
                  ip6-reachable-time: <value of integer>
                  ip6-retrans-time: <value of integer>
                  ip6-send-adv: <value in [disable, enable]>
                  ip6-subnet: <value of string>
                  ip6-upstream-interface: <value of string>
                  nd-cert: <value of string>
                  nd-cga-modifier: <value of string>
                  nd-mode: <value in [basic, SEND-compatible]>
                  nd-security-level: <value of integer>
                  nd-timestamp-delta: <value of integer>
                  nd-timestamp-fuzz: <value of integer>
                  unique-autoconf-addr: <value in [disable, enable]>
                  vrip6_link_local: <value of string>
                  vrrp-virtual-mac6: <value in [disable, enable]>
                  vrrp6:
                    -
                        accept-mode: <value in [disable, enable]>
                        adv-interval: <value of integer>
                        preempt: <value in [disable, enable]>
                        priority: <value of integer>
                        start-time: <value of integer>
                        status: <value in [disable, enable]>
                        vrdst6: <value of string>
                        vrgrp: <value of integer>
                        vrid: <value of integer>
                        vrip6: <value of string>
                  cli-conn6-status: <value of integer>
                  ip6-prefix-mode: <value in [dhcp6, ra]>
                  ra-send-mtu: <value in [disable, enable]>
                  ip6-delegated-prefix-iaid: <value of integer>
                  dhcp6-relay-source-interface: <value in [disable, enable]>
               l2forward: <value in [disable, enable]>
               l2tp-client: <value in [disable, enable]>
               lacp-ha-slave: <value in [disable, enable]>
               lacp-mode: <value in [static, passive, active]>
               lacp-speed: <value in [slow, fast]>
               lcp-echo-interval: <value of integer>
               lcp-max-echo-fails: <value of integer>
               link-up-delay: <value of integer>
               listen-forticlient-connection: <value in [disable, enable]>
               lldp-network-policy: <value of string>
               lldp-reception: <value in [disable, enable, vdom]>
               lldp-transmission: <value in [enable, disable, vdom]>
               log: <value in [disable, enable]>
               macaddr: <value of string>
               managed-subnetwork-size: <value in [256, 512, 1024, ...]>
               management-ip: <value of string>
               max-egress-burst-rate: <value of integer>
               max-egress-rate: <value of integer>
               measured-downstream-bandwidth: <value of integer>
               measured-upstream-bandwidth: <value of integer>
               mediatype: <value in [serdes-sfp, sgmii-sfp, cfp2-sr10, ...]>
               member: <value of string>
               min-links: <value of integer>
               min-links-down: <value in [operational, administrative]>
               mode: <value in [static, dhcp, pppoe, ...]>
               monitor-bandwidth: <value in [disable, enable]>
               mtu: <value of integer>
               mtu-override: <value in [disable, enable]>
               mux-type: <value in [llc-encaps, vc-encaps]>
               name: <value of string>
               ndiscforward: <value in [disable, enable]>
               netbios-forward: <value in [disable, enable]>
               netflow-sampler: <value in [disable, tx, rx, ...]>
               np-qos-profile: <value of integer>
               npu-fastpath: <value in [disable, enable]>
               nst: <value in [disable, enable]>
               out-force-vlan-cos: <value of integer>
               outbandwidth: <value of integer>
               padt-retry-timeout: <value of integer>
               password: <value of string>
               peer-interface: <value of string>
               phy-mode: <value in [auto, adsl, vdsl, ...]>
               ping-serv-status: <value of integer>
               poe: <value in [disable, enable]>
               polling-interval: <value of integer>
               pppoe-unnumbered-negotiate: <value in [disable, enable]>
               pptp-auth-type: <value in [auto, pap, chap, ...]>
               pptp-client: <value in [disable, enable]>
               pptp-password: <value of string>
               pptp-server-ip: <value of string>
               pptp-timeout: <value of integer>
               pptp-user: <value of string>
               preserve-session-route: <value in [disable, enable]>
               priority: <value of integer>
               priority-override: <value in [disable, enable]>
               proxy-captive-portal: <value in [disable, enable]>
               redundant-interface: <value of string>
               remote-ip: <value of string>
               replacemsg-override-group: <value of string>
               retransmission: <value in [disable, enable]>
               ring-rx: <value of integer>
               ring-tx: <value of integer>
               role: <value in [lan, wan, dmz, ...]>
               sample-direction: <value in [rx, tx, both]>
               sample-rate: <value of integer>
               scan-botnet-connections: <value in [disable, block, monitor]>
               secondary-IP: <value in [disable, enable]>
               secondaryip:
                 -
                     allowaccess:
                       - https
                       - ping
                       - ssh
                       - snmp
                       - http
                       - telnet
                       - fgfm
                       - auto-ipsec
                       - radius-acct
                       - probe-response
                       - capwap
                       - dnp
                       - ftm
                       - fabric
                       - speed-test
                     detectprotocol:
                       - ping
                       - tcp-echo
                       - udp-echo
                     detectserver: <value of string>
                     gwdetect: <value in [disable, enable]>
                     ha-priority: <value of integer>
                     id: <value of integer>
                     ip: <value of string>
                     ping-serv-status: <value of integer>
                     seq: <value of integer>
                     secip-relay-ip: <value of string>
               security-8021x-dynamic-vlan-id: <value of integer>
               security-8021x-master: <value of string>
               security-8021x-mode: <value in [default, dynamic-vlan, fallback, ...]>
               security-exempt-list: <value of string>
               security-external-logout: <value of string>
               security-external-web: <value of string>
               security-groups: <value of string>
               security-mac-auth-bypass: <value in [disable, enable, mac-auth-only]>
               security-mode: <value in [none, captive-portal, 802.1X]>
               security-redirect-url: <value of string>
               service-name: <value of string>
               sflow-sampler: <value in [disable, enable]>
               speed: <value in [auto, 10full, 10half, ...]>
               spillover-threshold: <value of integer>
               src-check: <value in [disable, enable]>
               status: <value in [down, up]>
               stp: <value in [disable, enable]>
               stp-ha-slave: <value in [disable, enable, priority-adjust]>
               stpforward: <value in [disable, enable]>
               stpforward-mode: <value in [rpl-all-ext-id, rpl-bridge-ext-id, rpl-nothing]>
               strip-priority-vlan-tag: <value in [disable, enable]>
               subst: <value in [disable, enable]>
               substitute-dst-mac: <value of string>
               swc-first-create: <value of integer>
               swc-vlan: <value of integer>
               switch: <value of string>
               switch-controller-access-vlan: <value in [disable, enable]>
               switch-controller-arp-inspection: <value in [disable, enable]>
               switch-controller-auth: <value in [radius, usergroup]>
               switch-controller-dhcp-snooping: <value in [disable, enable]>
               switch-controller-dhcp-snooping-option82: <value in [disable, enable]>
               switch-controller-dhcp-snooping-verify-mac: <value in [disable, enable]>
               switch-controller-feature: <value in [none, default-vlan, quarantine, ...]>
               switch-controller-igmp-snooping: <value in [disable, enable]>
               switch-controller-igmp-snooping-fast-leave: <value in [disable, enable]>
               switch-controller-igmp-snooping-proxy: <value in [disable, enable]>
               switch-controller-iot-scanning: <value in [disable, enable]>
               switch-controller-learning-limit: <value of integer>
               switch-controller-mgmt-vlan: <value of integer>
               switch-controller-nac: <value of string>
               switch-controller-radius-server: <value of string>
               switch-controller-rspan-mode: <value in [disable, enable]>
               switch-controller-source-ip: <value in [outbound, fixed]>
               switch-controller-traffic-policy: <value of string>
               tc-mode: <value in [ptm, atm]>
               tcp-mss: <value of integer>
               trunk: <value in [disable, enable]>
               trust-ip-1: <value of string>
               trust-ip-2: <value of string>
               trust-ip-3: <value of string>
               trust-ip6-1: <value of string>
               trust-ip6-2: <value of string>
               trust-ip6-3: <value of string>
               type: <value in [physical, vlan, aggregate, ...]>
               username: <value of string>
               vci: <value of integer>
               vectoring: <value in [disable, enable]>
               vindex: <value of integer>
               vlan-protocol: <value in [8021q, 8021ad]>
               vlanforward: <value in [disable, enable]>
               vlanid: <value of integer>
               vpi: <value of integer>
               vrf: <value of integer>
               vrrp:
                 -
                     accept-mode: <value in [disable, enable]>
                     adv-interval: <value of integer>
                     ignore-default-route: <value in [disable, enable]>
                     preempt: <value in [disable, enable]>
                     priority: <value of integer>
                     start-time: <value of integer>
                     status: <value in [disable, enable]>
                     version: <value in [2, 3]>
                     vrdst: <value of string>
                     vrdst-priority: <value of integer>
                     vrgrp: <value of integer>
                     vrid: <value of integer>
                     vrip: <value of string>
                     proxy-arp:
                       -
                           id: <value of integer>
                           ip: <value of string>
               vrrp-virtual-mac: <value in [disable, enable]>
               wccp: <value in [disable, enable]>
               weight: <value of integer>
               wifi-5g-threshold: <value of string>
               wifi-acl: <value in [deny, allow]>
               wifi-ap-band: <value in [any, 5g-preferred, 5g-only]>
               wifi-auth: <value in [PSK, RADIUS, radius, ...]>
               wifi-auto-connect: <value in [disable, enable]>
               wifi-auto-save: <value in [disable, enable]>
               wifi-broadcast-ssid: <value in [disable, enable]>
               wifi-encrypt: <value in [TKIP, AES]>
               wifi-fragment-threshold: <value of integer>
               wifi-key: <value of string>
               wifi-keyindex: <value of integer>
               wifi-mac-filter: <value in [disable, enable]>
               wifi-passphrase: <value of string>
               wifi-radius-server: <value of string>
               wifi-rts-threshold: <value of integer>
               wifi-security: <value in [None, WEP64, wep64, ...]>
               wifi-ssid: <value of string>
               wifi-usergroup: <value of string>
               wins-ip: <value of string>
               dhcp-relay-request-all-server: <value in [disable, enable]>
               stp-ha-secondary: <value in [disable, enable, priority-adjust]>
               switch-controller-dynamic: <value of string>
               auth-cert: <value of string>
               auth-portal-addr: <value of string>
               dhcp-classless-route-addition: <value in [disable, enable]>
               dhcp-relay-link-selection: <value of string>
               dns-server-protocol:
                 - cleartext
                 - dot
                 - doh
               eap-ca-cert: <value of string>
               eap-identity: <value of string>
               eap-method: <value in [tls, peap]>
               eap-password: <value of string>
               eap-supplicant: <value in [disable, enable]>
               eap-user-cert: <value of string>
               ike-saml-server: <value of string>
               lacp-ha-secondary: <value in [disable, enable]>
               pvc-atm-qos: <value in [cbr, rt-vbr, nrt-vbr]>
               pvc-chan: <value of integer>
               pvc-crc: <value of integer>
               pvc-pcr: <value of integer>
               pvc-scr: <value of integer>
               pvc-vlan-id: <value of integer>
               pvc-vlan-rx-id: <value of integer>
               pvc-vlan-rx-op: <value in [pass-through, replace, remove]>
               pvc-vlan-tx-id: <value of integer>
               pvc-vlan-tx-op: <value in [pass-through, replace, remove]>
               reachable-time: <value of integer>
               select-profile-30a-35b: <value in [30A, 35B]>
               sfp-dsl: <value in [disable, enable]>
               sfp-dsl-adsl-fallback: <value in [disable, enable]>
               sfp-dsl-autodetect: <value in [disable, enable]>
               sfp-dsl-mac: <value of string>
               sw-algorithm: <value in [l2, l3, eh]>
               system-id: <value of string>
               system-id-type: <value in [auto, user]>
               vlan-id: <value of integer>
               vlan-op-mode: <value in [tag, untag, passthrough]>
               generic-receive-offload: <value in [disable, enable]>
               interconnect-profile: <value in [default, profile1, profile2]>
               large-receive-offload: <value in [disable, enable]>
               aggregate-type: <value in [physical, vxlan]>
               switch-controller-netflow-collect: <value in [disable, enable]>
               wifi-dns-server1: <value of string>
               wifi-dns-server2: <value of string>
               wifi-gateway: <value of string>
               default-purdue-level: <value in [1, 2, 3, ...]>
               dhcp-broadcast-flag: <value in [disable, enable]>
               dhcp-smart-relay: <value in [disable, enable]>
               switch-controller-offloading: <value in [disable, enable]>
               switch-controller-offloading-gw: <value in [disable, enable]>
               switch-controller-offloading-ip: <value of string>

'''

RETURN = '''
meta:
    description: The result of the request.
    type: dict
    returned: always
    contains:
        request_url:
            description: The full url requested.
            returned: always
            type: str
            sample: /sys/login/user
        response_code:
            description: The status of api request.
            returned: always
            type: int
            sample: 0
        response_data:
            description: The api response.
            type: list
            returned: always
        response_message:
            description: The descriptive message of the api response.
            type: str
            returned: always
            sample: OK.
        system_information:
            description: The information of the target system.
            type: dict
            returned: always
rc:
    description: The status the request.
    type: int
    returned: always
    sample: 0
version_check_warning:
    description: Warning if the parameters used in the playbook are not supported by the current FortiManager version.
    type: list
    returned: complex
'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_galaxy_version
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_parameter_bypass


def main():
    jrpc_urls = [
        '/pm/config/adom/{adom}/obj/fsp/vlan',
        '/pm/config/global/obj/fsp/vlan'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}',
        '/pm/config/global/obj/fsp/vlan/{vlan}'
    ]

    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'access_token': {
            'type': 'str',
            'required': False,
            'no_log': True
        },
        'bypass_validation': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'enable_log': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'forticloud_access_token': {
            'type': 'str',
            'required': False,
            'no_log': True
        },
        'proposed_method': {
            'type': 'str',
            'required': False,
            'choices': [
                'set',
                'update',
                'add'
            ]
        },
        'rc_succeeded': {
            'required': False,
            'type': 'list',
            'elements': 'int'
        },
        'rc_failed': {
            'required': False,
            'type': 'list',
            'elements': 'int'
        },
        'state': {
            'type': 'str',
            'required': True,
            'choices': [
                'present',
                'absent'
            ]
        },
        'workspace_locking_adom': {
            'type': 'str',
            'required': False
        },
        'workspace_locking_timeout': {
            'type': 'int',
            'required': False,
            'default': 300
        },
        'adom': {
            'required': True,
            'type': 'str'
        },
        'fsp_vlan': {
            'required': False,
            'type': 'dict',
            'revision': {
                '6.0.0': True,
                '6.2.0': True,
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.6': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True,
                '6.4.0': True,
                '6.4.1': True,
                '6.4.2': True,
                '6.4.3': True,
                '6.4.4': True,
                '6.4.5': True,
                '6.4.6': True,
                '6.4.7': True,
                '6.4.8': True,
                '6.4.9': True,
                '6.4.10': True,
                '6.4.11': True,
                '7.0.0': True,
                '7.0.1': True,
                '7.0.2': True,
                '7.0.3': True,
                '7.0.4': True,
                '7.0.5': True,
                '7.0.6': True,
                '7.0.7': True,
                '7.2.0': True,
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'options': {
                '_dhcp-status': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'auth': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': False,
                        '6.2.5': False,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False,
                        '6.2.0': True,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.4.1': False,
                        '6.4.3': False,
                        '6.4.4': False,
                        '6.4.6': False,
                        '6.4.7': False,
                        '6.4.8': False,
                        '6.4.9': False,
                        '6.4.10': False,
                        '6.4.11': False,
                        '7.0.1': False,
                        '7.0.2': False,
                        '7.0.3': False,
                        '7.0.4': False,
                        '7.0.5': False,
                        '7.0.6': False,
                        '7.0.7': False,
                        '7.2.1': False,
                        '7.2.2': False,
                        '7.4.0': False
                    },
                    'choices': [
                        'radius',
                        'usergroup'
                    ],
                    'type': 'str'
                },
                'color': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'comments': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': False,
                        '6.2.5': False,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False,
                        '6.2.0': True,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.4.1': False,
                        '6.4.3': False,
                        '6.4.4': False,
                        '6.4.6': False,
                        '6.4.7': False,
                        '6.4.8': False,
                        '6.4.9': False,
                        '6.4.10': False,
                        '6.4.11': False,
                        '7.0.1': False,
                        '7.0.2': False,
                        '7.0.3': False,
                        '7.0.4': False,
                        '7.0.5': False,
                        '7.0.6': False,
                        '7.0.7': False,
                        '7.2.1': False,
                        '7.2.2': False,
                        '7.4.0': False
                    },
                    'type': 'str'
                },
                'dynamic_mapping': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'list',
                    'options': {
                        '_dhcp-status': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': True,
                                '6.2.2': True,
                                '6.2.6': True,
                                '6.2.7': True,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        '_scope': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': True,
                                '6.2.2': True,
                                '6.2.6': True,
                                '6.2.7': True,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'list',
                            'options': {
                                'name': {
                                    'required': False,
                                    'revision': {
                                        '6.0.0': True,
                                        '6.2.1': True,
                                        '6.2.3': True,
                                        '6.2.5': True,
                                        '6.4.0': True,
                                        '6.4.2': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': True,
                                        '6.2.2': True,
                                        '6.2.6': True,
                                        '6.2.7': True,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': True,
                                        '6.4.3': True,
                                        '6.4.4': True,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'vdom': {
                                    'required': False,
                                    'revision': {
                                        '6.0.0': True,
                                        '6.2.1': True,
                                        '6.2.3': True,
                                        '6.2.5': True,
                                        '6.4.0': True,
                                        '6.4.2': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': True,
                                        '6.2.2': True,
                                        '6.2.6': True,
                                        '6.2.7': True,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': True,
                                        '6.4.3': True,
                                        '6.4.4': True,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                }
                            },
                            'elements': 'dict'
                        },
                        'dhcp-server': {
                            'required': False,
                            'type': 'dict',
                            'options': {
                                'auto-configuration': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'auto-managed-status': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': False,
                                        '6.2.9': False,
                                        '6.2.10': False,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'conflicted-ip-timeout': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'int'
                                },
                                'ddns-auth': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'choices': [
                                        'disable',
                                        'tsig'
                                    ],
                                    'type': 'str'
                                },
                                'ddns-key': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'ddns-keyname': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'ddns-server-ip': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'ddns-ttl': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'int'
                                },
                                'ddns-update': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'ddns-update-override': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'ddns-zone': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'default-gateway': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'dhcp-settings-from-fortiipam': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': False,
                                        '6.2.9': False,
                                        '6.2.10': False,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'dns-server1': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'dns-server2': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'dns-server3': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'dns-server4': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'dns-service': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'choices': [
                                        'default',
                                        'specify',
                                        'local'
                                    ],
                                    'type': 'str'
                                },
                                'domain': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'enable': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'exclude-range': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'list',
                                    'options': {
                                        'end-ip': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'id': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'start-ip': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'vci-match': {
                                            'required': False,
                                            'revision': {
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'choices': [
                                                'disable',
                                                'enable'
                                            ],
                                            'type': 'str'
                                        },
                                        'vci-string': {
                                            'required': False,
                                            'revision': {
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'lease-time': {
                                            'required': False,
                                            'revision': {
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'uci-match': {
                                            'required': False,
                                            'revision': {
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'choices': [
                                                'disable',
                                                'enable'
                                            ],
                                            'type': 'str'
                                        },
                                        'uci-string': {
                                            'required': False,
                                            'revision': {
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'str'
                                        }
                                    },
                                    'elements': 'dict'
                                },
                                'filename': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'forticlient-on-net-status': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'id': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'int'
                                },
                                'ip-mode': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'choices': [
                                        'range',
                                        'usrgrp'
                                    ],
                                    'type': 'str'
                                },
                                'ip-range': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'list',
                                    'options': {
                                        'end-ip': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'id': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'start-ip': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'vci-match': {
                                            'required': False,
                                            'revision': {
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'choices': [
                                                'disable',
                                                'enable'
                                            ],
                                            'type': 'str'
                                        },
                                        'vci-string': {
                                            'required': False,
                                            'revision': {
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'lease-time': {
                                            'required': False,
                                            'revision': {
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'uci-match': {
                                            'required': False,
                                            'revision': {
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'choices': [
                                                'disable',
                                                'enable'
                                            ],
                                            'type': 'str'
                                        },
                                        'uci-string': {
                                            'required': False,
                                            'revision': {
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'str'
                                        }
                                    },
                                    'elements': 'dict'
                                },
                                'ipsec-lease-hold': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'int'
                                },
                                'lease-time': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'int'
                                },
                                'mac-acl-default-action': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'choices': [
                                        'assign',
                                        'block'
                                    ],
                                    'type': 'str'
                                },
                                'netmask': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'next-server': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'ntp-server1': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'ntp-server2': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'ntp-server3': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'ntp-service': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'choices': [
                                        'default',
                                        'specify',
                                        'local'
                                    ],
                                    'type': 'str'
                                },
                                'option1': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'option2': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'option3': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'option4': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'option5': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'option6': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'options': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'list',
                                    'options': {
                                        'code': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'id': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'ip': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'type': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'choices': [
                                                'hex',
                                                'string',
                                                'ip',
                                                'fqdn'
                                            ],
                                            'type': 'str'
                                        },
                                        'value': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'vci-match': {
                                            'required': False,
                                            'revision': {
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'choices': [
                                                'disable',
                                                'enable'
                                            ],
                                            'type': 'str'
                                        },
                                        'vci-string': {
                                            'required': False,
                                            'revision': {
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'uci-match': {
                                            'required': False,
                                            'revision': {
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'choices': [
                                                'disable',
                                                'enable'
                                            ],
                                            'type': 'str'
                                        },
                                        'uci-string': {
                                            'required': False,
                                            'revision': {
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'str'
                                        }
                                    },
                                    'elements': 'dict'
                                },
                                'reserved-address': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'list',
                                    'options': {
                                        'action': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'choices': [
                                                'assign',
                                                'block',
                                                'reserved'
                                            ],
                                            'type': 'str'
                                        },
                                        'circuit-id': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'circuit-id-type': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'choices': [
                                                'hex',
                                                'string'
                                            ],
                                            'type': 'str'
                                        },
                                        'description': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'id': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'ip': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'mac': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'remote-id': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'remote-id-type': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'choices': [
                                                'hex',
                                                'string'
                                            ],
                                            'type': 'str'
                                        },
                                        'type': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'choices': [
                                                'mac',
                                                'option82'
                                            ],
                                            'type': 'str'
                                        }
                                    },
                                    'elements': 'dict'
                                },
                                'server-type': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'choices': [
                                        'regular',
                                        'ipsec'
                                    ],
                                    'type': 'str'
                                },
                                'status': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'tftp-server': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'timezone': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'choices': [
                                        '00',
                                        '01',
                                        '02',
                                        '03',
                                        '04',
                                        '05',
                                        '06',
                                        '07',
                                        '08',
                                        '09',
                                        '10',
                                        '11',
                                        '12',
                                        '13',
                                        '14',
                                        '15',
                                        '16',
                                        '17',
                                        '18',
                                        '19',
                                        '20',
                                        '21',
                                        '22',
                                        '23',
                                        '24',
                                        '25',
                                        '26',
                                        '27',
                                        '28',
                                        '29',
                                        '30',
                                        '31',
                                        '32',
                                        '33',
                                        '34',
                                        '35',
                                        '36',
                                        '37',
                                        '38',
                                        '39',
                                        '40',
                                        '41',
                                        '42',
                                        '43',
                                        '44',
                                        '45',
                                        '46',
                                        '47',
                                        '48',
                                        '49',
                                        '50',
                                        '51',
                                        '52',
                                        '53',
                                        '54',
                                        '55',
                                        '56',
                                        '57',
                                        '58',
                                        '59',
                                        '60',
                                        '61',
                                        '62',
                                        '63',
                                        '64',
                                        '65',
                                        '66',
                                        '67',
                                        '68',
                                        '69',
                                        '70',
                                        '71',
                                        '72',
                                        '73',
                                        '74',
                                        '75',
                                        '76',
                                        '77',
                                        '78',
                                        '79',
                                        '80',
                                        '81',
                                        '82',
                                        '83',
                                        '84',
                                        '85',
                                        '86',
                                        '87'
                                    ],
                                    'type': 'str'
                                },
                                'timezone-option': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'choices': [
                                        'disable',
                                        'default',
                                        'specify'
                                    ],
                                    'type': 'str'
                                },
                                'vci-match': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'vci-string': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'wifi-ac-service': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'choices': [
                                        'specify',
                                        'local'
                                    ],
                                    'type': 'str'
                                },
                                'wifi-ac1': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'wifi-ac2': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'wifi-ac3': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'wins-server1': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'wins-server2': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'relay-agent': {
                                    'required': False,
                                    'revision': {
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'shared-subnet': {
                                    'required': False,
                                    'revision': {
                                        '7.4.0': True
                                    },
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                }
                            }
                        },
                        'interface': {
                            'required': False,
                            'type': 'dict',
                            'options': {
                                'dhcp-relay-agent-option': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'dhcp-relay-ip': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'dhcp-relay-service': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'dhcp-relay-type': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'choices': [
                                        'regular',
                                        'ipsec'
                                    ],
                                    'type': 'str'
                                },
                                'ip': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'ipv6': {
                                    'required': False,
                                    'type': 'dict',
                                    'options': {
                                        'autoconf': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'choices': [
                                                'disable',
                                                'enable'
                                            ],
                                            'type': 'str'
                                        },
                                        'dhcp6-client-options': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'list',
                                            'choices': [
                                                'rapid',
                                                'iapd',
                                                'iana',
                                                'dns',
                                                'dnsname'
                                            ],
                                            'elements': 'str'
                                        },
                                        'dhcp6-information-request': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'choices': [
                                                'disable',
                                                'enable'
                                            ],
                                            'type': 'str'
                                        },
                                        'dhcp6-prefix-delegation': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'choices': [
                                                'disable',
                                                'enable'
                                            ],
                                            'type': 'str'
                                        },
                                        'dhcp6-prefix-hint': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'dhcp6-prefix-hint-plt': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'dhcp6-prefix-hint-vlt': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'dhcp6-relay-ip': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'dhcp6-relay-service': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'choices': [
                                                'disable',
                                                'enable'
                                            ],
                                            'type': 'str'
                                        },
                                        'dhcp6-relay-type': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'choices': [
                                                'regular'
                                            ],
                                            'type': 'str'
                                        },
                                        'icmp6-send-redirect': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': False,
                                                '6.2.9': False,
                                                '6.2.10': False,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'choices': [
                                                'disable',
                                                'enable'
                                            ],
                                            'type': 'str'
                                        },
                                        'interface-identifier': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': False,
                                                '6.2.9': False,
                                                '6.2.10': False,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'ip6-address': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'ip6-allowaccess': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'list',
                                            'choices': [
                                                'https',
                                                'ping',
                                                'ssh',
                                                'snmp',
                                                'http',
                                                'telnet',
                                                'fgfm',
                                                'capwap',
                                                'fabric'
                                            ],
                                            'elements': 'str'
                                        },
                                        'ip6-default-life': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'ip6-delegated-prefix-list': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'list',
                                            'options': {
                                                'autonomous-flag': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True,
                                                        '6.2.0': False,
                                                        '6.2.2': False,
                                                        '6.2.6': False,
                                                        '6.2.7': False,
                                                        '6.2.8': True,
                                                        '6.2.9': True,
                                                        '6.2.10': True,
                                                        '6.4.1': False,
                                                        '6.4.3': False,
                                                        '6.4.4': False,
                                                        '6.4.6': True,
                                                        '6.4.7': True,
                                                        '6.4.8': True,
                                                        '6.4.9': True,
                                                        '6.4.10': True,
                                                        '6.4.11': True,
                                                        '7.0.1': True,
                                                        '7.0.2': True,
                                                        '7.0.3': True,
                                                        '7.0.4': True,
                                                        '7.0.5': True,
                                                        '7.0.6': True,
                                                        '7.0.7': True,
                                                        '7.2.1': True,
                                                        '7.2.2': True,
                                                        '7.4.0': True
                                                    },
                                                    'choices': [
                                                        'disable',
                                                        'enable'
                                                    ],
                                                    'type': 'str'
                                                },
                                                'onlink-flag': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True,
                                                        '6.2.0': False,
                                                        '6.2.2': False,
                                                        '6.2.6': False,
                                                        '6.2.7': False,
                                                        '6.2.8': True,
                                                        '6.2.9': True,
                                                        '6.2.10': True,
                                                        '6.4.1': False,
                                                        '6.4.3': False,
                                                        '6.4.4': False,
                                                        '6.4.6': True,
                                                        '6.4.7': True,
                                                        '6.4.8': True,
                                                        '6.4.9': True,
                                                        '6.4.10': True,
                                                        '6.4.11': True,
                                                        '7.0.1': True,
                                                        '7.0.2': True,
                                                        '7.0.3': True,
                                                        '7.0.4': True,
                                                        '7.0.5': True,
                                                        '7.0.6': True,
                                                        '7.0.7': True,
                                                        '7.2.1': True,
                                                        '7.2.2': True,
                                                        '7.4.0': True
                                                    },
                                                    'choices': [
                                                        'disable',
                                                        'enable'
                                                    ],
                                                    'type': 'str'
                                                },
                                                'prefix-id': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True,
                                                        '6.2.0': False,
                                                        '6.2.2': False,
                                                        '6.2.6': False,
                                                        '6.2.7': False,
                                                        '6.2.8': True,
                                                        '6.2.9': True,
                                                        '6.2.10': True,
                                                        '6.4.1': False,
                                                        '6.4.3': False,
                                                        '6.4.4': False,
                                                        '6.4.6': True,
                                                        '6.4.7': True,
                                                        '6.4.8': True,
                                                        '6.4.9': True,
                                                        '6.4.10': True,
                                                        '6.4.11': True,
                                                        '7.0.1': True,
                                                        '7.0.2': True,
                                                        '7.0.3': True,
                                                        '7.0.4': True,
                                                        '7.0.5': True,
                                                        '7.0.6': True,
                                                        '7.0.7': True,
                                                        '7.2.1': True,
                                                        '7.2.2': True,
                                                        '7.4.0': True
                                                    },
                                                    'type': 'int'
                                                },
                                                'rdnss': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True,
                                                        '6.2.0': False,
                                                        '6.2.2': False,
                                                        '6.2.6': False,
                                                        '6.2.7': False,
                                                        '6.2.8': True,
                                                        '6.2.9': True,
                                                        '6.2.10': True,
                                                        '6.4.1': False,
                                                        '6.4.3': False,
                                                        '6.4.4': False,
                                                        '6.4.6': True,
                                                        '6.4.7': True,
                                                        '6.4.8': True,
                                                        '6.4.9': True,
                                                        '6.4.10': True,
                                                        '6.4.11': True,
                                                        '7.0.1': True,
                                                        '7.0.2': True,
                                                        '7.0.3': True,
                                                        '7.0.4': True,
                                                        '7.0.5': True,
                                                        '7.0.6': True,
                                                        '7.0.7': True,
                                                        '7.2.1': True,
                                                        '7.2.2': True,
                                                        '7.4.0': True
                                                    },
                                                    'type': 'str'
                                                },
                                                'rdnss-service': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True,
                                                        '6.2.0': False,
                                                        '6.2.2': False,
                                                        '6.2.6': False,
                                                        '6.2.7': False,
                                                        '6.2.8': True,
                                                        '6.2.9': True,
                                                        '6.2.10': True,
                                                        '6.4.1': False,
                                                        '6.4.3': False,
                                                        '6.4.4': False,
                                                        '6.4.6': True,
                                                        '6.4.7': True,
                                                        '6.4.8': True,
                                                        '6.4.9': True,
                                                        '6.4.10': True,
                                                        '6.4.11': True,
                                                        '7.0.1': True,
                                                        '7.0.2': True,
                                                        '7.0.3': True,
                                                        '7.0.4': True,
                                                        '7.0.5': True,
                                                        '7.0.6': True,
                                                        '7.0.7': True,
                                                        '7.2.1': True,
                                                        '7.2.2': True,
                                                        '7.4.0': True
                                                    },
                                                    'choices': [
                                                        'delegated',
                                                        'default',
                                                        'specify'
                                                    ],
                                                    'type': 'str'
                                                },
                                                'subnet': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True,
                                                        '6.2.0': False,
                                                        '6.2.2': False,
                                                        '6.2.6': False,
                                                        '6.2.7': False,
                                                        '6.2.8': True,
                                                        '6.2.9': True,
                                                        '6.2.10': True,
                                                        '6.4.1': False,
                                                        '6.4.3': False,
                                                        '6.4.4': False,
                                                        '6.4.6': True,
                                                        '6.4.7': True,
                                                        '6.4.8': True,
                                                        '6.4.9': True,
                                                        '6.4.10': True,
                                                        '6.4.11': True,
                                                        '7.0.1': True,
                                                        '7.0.2': True,
                                                        '7.0.3': True,
                                                        '7.0.4': True,
                                                        '7.0.5': True,
                                                        '7.0.6': True,
                                                        '7.0.7': True,
                                                        '7.2.1': True,
                                                        '7.2.2': True,
                                                        '7.4.0': True
                                                    },
                                                    'type': 'str'
                                                },
                                                'upstream-interface': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True,
                                                        '6.2.0': False,
                                                        '6.2.2': False,
                                                        '6.2.6': False,
                                                        '6.2.7': False,
                                                        '6.2.8': True,
                                                        '6.2.9': True,
                                                        '6.2.10': True,
                                                        '6.4.1': False,
                                                        '6.4.3': False,
                                                        '6.4.4': False,
                                                        '6.4.6': True,
                                                        '6.4.7': True,
                                                        '6.4.8': True,
                                                        '6.4.9': True,
                                                        '6.4.10': True,
                                                        '6.4.11': True,
                                                        '7.0.1': True,
                                                        '7.0.2': True,
                                                        '7.0.3': True,
                                                        '7.0.4': True,
                                                        '7.0.5': True,
                                                        '7.0.6': True,
                                                        '7.0.7': True,
                                                        '7.2.1': True,
                                                        '7.2.2': True,
                                                        '7.4.0': True
                                                    },
                                                    'type': 'str'
                                                },
                                                'delegated-prefix-iaid': {
                                                    'required': False,
                                                    'revision': {
                                                        '7.2.0': True,
                                                        '6.2.0': False,
                                                        '6.2.2': False,
                                                        '6.2.6': False,
                                                        '6.2.7': False,
                                                        '6.2.8': False,
                                                        '6.2.9': False,
                                                        '6.2.10': False,
                                                        '6.4.1': False,
                                                        '6.4.3': False,
                                                        '6.4.4': False,
                                                        '6.4.6': False,
                                                        '6.4.7': False,
                                                        '6.4.8': False,
                                                        '6.4.9': False,
                                                        '6.4.10': False,
                                                        '6.4.11': False,
                                                        '7.0.1': False,
                                                        '7.0.2': True,
                                                        '7.0.3': True,
                                                        '7.0.4': True,
                                                        '7.0.5': True,
                                                        '7.0.6': True,
                                                        '7.0.7': True,
                                                        '7.2.1': True,
                                                        '7.2.2': True,
                                                        '7.4.0': True
                                                    },
                                                    'type': 'int'
                                                }
                                            },
                                            'elements': 'dict'
                                        },
                                        'ip6-dns-server-override': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'choices': [
                                                'disable',
                                                'enable'
                                            ],
                                            'type': 'str'
                                        },
                                        'ip6-extra-addr': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'list',
                                            'options': {
                                                'prefix': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True,
                                                        '6.2.0': False,
                                                        '6.2.2': False,
                                                        '6.2.6': False,
                                                        '6.2.7': False,
                                                        '6.2.8': True,
                                                        '6.2.9': True,
                                                        '6.2.10': True,
                                                        '6.4.1': False,
                                                        '6.4.3': False,
                                                        '6.4.4': False,
                                                        '6.4.6': True,
                                                        '6.4.7': True,
                                                        '6.4.8': True,
                                                        '6.4.9': True,
                                                        '6.4.10': True,
                                                        '6.4.11': True,
                                                        '7.0.1': True,
                                                        '7.0.2': True,
                                                        '7.0.3': True,
                                                        '7.0.4': True,
                                                        '7.0.5': True,
                                                        '7.0.6': True,
                                                        '7.0.7': True,
                                                        '7.2.1': True,
                                                        '7.2.2': True,
                                                        '7.4.0': True
                                                    },
                                                    'type': 'str'
                                                }
                                            },
                                            'elements': 'dict'
                                        },
                                        'ip6-hop-limit': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'ip6-link-mtu': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'ip6-manage-flag': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'choices': [
                                                'disable',
                                                'enable'
                                            ],
                                            'type': 'str'
                                        },
                                        'ip6-max-interval': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'ip6-min-interval': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'ip6-mode': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'choices': [
                                                'static',
                                                'dhcp',
                                                'pppoe',
                                                'delegated'
                                            ],
                                            'type': 'str'
                                        },
                                        'ip6-other-flag': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'choices': [
                                                'disable',
                                                'enable'
                                            ],
                                            'type': 'str'
                                        },
                                        'ip6-prefix-list': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'list',
                                            'options': {
                                                'autonomous-flag': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True,
                                                        '6.2.0': False,
                                                        '6.2.2': False,
                                                        '6.2.6': False,
                                                        '6.2.7': False,
                                                        '6.2.8': True,
                                                        '6.2.9': True,
                                                        '6.2.10': True,
                                                        '6.4.1': False,
                                                        '6.4.3': False,
                                                        '6.4.4': False,
                                                        '6.4.6': True,
                                                        '6.4.7': True,
                                                        '6.4.8': True,
                                                        '6.4.9': True,
                                                        '6.4.10': True,
                                                        '6.4.11': True,
                                                        '7.0.1': True,
                                                        '7.0.2': True,
                                                        '7.0.3': True,
                                                        '7.0.4': True,
                                                        '7.0.5': True,
                                                        '7.0.6': True,
                                                        '7.0.7': True,
                                                        '7.2.1': True,
                                                        '7.2.2': True,
                                                        '7.4.0': True
                                                    },
                                                    'choices': [
                                                        'disable',
                                                        'enable'
                                                    ],
                                                    'type': 'str'
                                                },
                                                'dnssl': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True,
                                                        '6.2.0': False,
                                                        '6.2.2': False,
                                                        '6.2.6': False,
                                                        '6.2.7': False,
                                                        '6.2.8': True,
                                                        '6.2.9': True,
                                                        '6.2.10': True,
                                                        '6.4.1': False,
                                                        '6.4.3': False,
                                                        '6.4.4': False,
                                                        '6.4.6': True,
                                                        '6.4.7': True,
                                                        '6.4.8': True,
                                                        '6.4.9': True,
                                                        '6.4.10': True,
                                                        '6.4.11': True,
                                                        '7.0.1': True,
                                                        '7.0.2': True,
                                                        '7.0.3': True,
                                                        '7.0.4': True,
                                                        '7.0.5': True,
                                                        '7.0.6': True,
                                                        '7.0.7': True,
                                                        '7.2.1': True,
                                                        '7.2.2': True,
                                                        '7.4.0': True
                                                    },
                                                    'type': 'str'
                                                },
                                                'onlink-flag': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True,
                                                        '6.2.0': False,
                                                        '6.2.2': False,
                                                        '6.2.6': False,
                                                        '6.2.7': False,
                                                        '6.2.8': True,
                                                        '6.2.9': True,
                                                        '6.2.10': True,
                                                        '6.4.1': False,
                                                        '6.4.3': False,
                                                        '6.4.4': False,
                                                        '6.4.6': True,
                                                        '6.4.7': True,
                                                        '6.4.8': True,
                                                        '6.4.9': True,
                                                        '6.4.10': True,
                                                        '6.4.11': True,
                                                        '7.0.1': True,
                                                        '7.0.2': True,
                                                        '7.0.3': True,
                                                        '7.0.4': True,
                                                        '7.0.5': True,
                                                        '7.0.6': True,
                                                        '7.0.7': True,
                                                        '7.2.1': True,
                                                        '7.2.2': True,
                                                        '7.4.0': True
                                                    },
                                                    'choices': [
                                                        'disable',
                                                        'enable'
                                                    ],
                                                    'type': 'str'
                                                },
                                                'preferred-life-time': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True,
                                                        '6.2.0': False,
                                                        '6.2.2': False,
                                                        '6.2.6': False,
                                                        '6.2.7': False,
                                                        '6.2.8': True,
                                                        '6.2.9': True,
                                                        '6.2.10': True,
                                                        '6.4.1': False,
                                                        '6.4.3': False,
                                                        '6.4.4': False,
                                                        '6.4.6': True,
                                                        '6.4.7': True,
                                                        '6.4.8': True,
                                                        '6.4.9': True,
                                                        '6.4.10': True,
                                                        '6.4.11': True,
                                                        '7.0.1': True,
                                                        '7.0.2': True,
                                                        '7.0.3': True,
                                                        '7.0.4': True,
                                                        '7.0.5': True,
                                                        '7.0.6': True,
                                                        '7.0.7': True,
                                                        '7.2.1': True,
                                                        '7.2.2': True,
                                                        '7.4.0': True
                                                    },
                                                    'type': 'int'
                                                },
                                                'prefix': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True,
                                                        '6.2.0': False,
                                                        '6.2.2': False,
                                                        '6.2.6': False,
                                                        '6.2.7': False,
                                                        '6.2.8': True,
                                                        '6.2.9': True,
                                                        '6.2.10': True,
                                                        '6.4.1': False,
                                                        '6.4.3': False,
                                                        '6.4.4': False,
                                                        '6.4.6': True,
                                                        '6.4.7': True,
                                                        '6.4.8': True,
                                                        '6.4.9': True,
                                                        '6.4.10': True,
                                                        '6.4.11': True,
                                                        '7.0.1': True,
                                                        '7.0.2': True,
                                                        '7.0.3': True,
                                                        '7.0.4': True,
                                                        '7.0.5': True,
                                                        '7.0.6': True,
                                                        '7.0.7': True,
                                                        '7.2.1': True,
                                                        '7.2.2': True,
                                                        '7.4.0': True
                                                    },
                                                    'type': 'str'
                                                },
                                                'rdnss': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True,
                                                        '6.2.0': False,
                                                        '6.2.2': False,
                                                        '6.2.6': False,
                                                        '6.2.7': False,
                                                        '6.2.8': True,
                                                        '6.2.9': True,
                                                        '6.2.10': True,
                                                        '6.4.1': False,
                                                        '6.4.3': False,
                                                        '6.4.4': False,
                                                        '6.4.6': True,
                                                        '6.4.7': True,
                                                        '6.4.8': True,
                                                        '6.4.9': True,
                                                        '6.4.10': True,
                                                        '6.4.11': True,
                                                        '7.0.1': True,
                                                        '7.0.2': True,
                                                        '7.0.3': True,
                                                        '7.0.4': True,
                                                        '7.0.5': True,
                                                        '7.0.6': True,
                                                        '7.0.7': True,
                                                        '7.2.1': True,
                                                        '7.2.2': True,
                                                        '7.4.0': True
                                                    },
                                                    'type': 'str'
                                                },
                                                'valid-life-time': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True,
                                                        '6.2.0': False,
                                                        '6.2.2': False,
                                                        '6.2.6': False,
                                                        '6.2.7': False,
                                                        '6.2.8': True,
                                                        '6.2.9': True,
                                                        '6.2.10': True,
                                                        '6.4.1': False,
                                                        '6.4.3': False,
                                                        '6.4.4': False,
                                                        '6.4.6': True,
                                                        '6.4.7': True,
                                                        '6.4.8': True,
                                                        '6.4.9': True,
                                                        '6.4.10': True,
                                                        '6.4.11': True,
                                                        '7.0.1': True,
                                                        '7.0.2': True,
                                                        '7.0.3': True,
                                                        '7.0.4': True,
                                                        '7.0.5': True,
                                                        '7.0.6': True,
                                                        '7.0.7': True,
                                                        '7.2.1': True,
                                                        '7.2.2': True,
                                                        '7.4.0': True
                                                    },
                                                    'type': 'int'
                                                }
                                            },
                                            'elements': 'dict'
                                        },
                                        'ip6-reachable-time': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'ip6-retrans-time': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'ip6-send-adv': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'choices': [
                                                'disable',
                                                'enable'
                                            ],
                                            'type': 'str'
                                        },
                                        'ip6-subnet': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'ip6-upstream-interface': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'nd-cert': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'nd-cga-modifier': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'nd-mode': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'choices': [
                                                'basic',
                                                'SEND-compatible'
                                            ],
                                            'type': 'str'
                                        },
                                        'nd-security-level': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'nd-timestamp-delta': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'nd-timestamp-fuzz': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'unique-autoconf-addr': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': False,
                                                '6.2.9': False,
                                                '6.2.10': False,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'choices': [
                                                'disable',
                                                'enable'
                                            ],
                                            'type': 'str'
                                        },
                                        'vrip6_link_local': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'vrrp-virtual-mac6': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'choices': [
                                                'disable',
                                                'enable'
                                            ],
                                            'type': 'str'
                                        },
                                        'vrrp6': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'list',
                                            'options': {
                                                'accept-mode': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True,
                                                        '6.2.0': False,
                                                        '6.2.2': False,
                                                        '6.2.6': False,
                                                        '6.2.7': False,
                                                        '6.2.8': True,
                                                        '6.2.9': True,
                                                        '6.2.10': True,
                                                        '6.4.1': False,
                                                        '6.4.3': False,
                                                        '6.4.4': False,
                                                        '6.4.6': True,
                                                        '6.4.7': True,
                                                        '6.4.8': True,
                                                        '6.4.9': True,
                                                        '6.4.10': True,
                                                        '6.4.11': True,
                                                        '7.0.1': True,
                                                        '7.0.2': True,
                                                        '7.0.3': True,
                                                        '7.0.4': True,
                                                        '7.0.5': True,
                                                        '7.0.6': True,
                                                        '7.0.7': True,
                                                        '7.2.1': True,
                                                        '7.2.2': True,
                                                        '7.4.0': True
                                                    },
                                                    'choices': [
                                                        'disable',
                                                        'enable'
                                                    ],
                                                    'type': 'str'
                                                },
                                                'adv-interval': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True,
                                                        '6.2.0': False,
                                                        '6.2.2': False,
                                                        '6.2.6': False,
                                                        '6.2.7': False,
                                                        '6.2.8': True,
                                                        '6.2.9': True,
                                                        '6.2.10': True,
                                                        '6.4.1': False,
                                                        '6.4.3': False,
                                                        '6.4.4': False,
                                                        '6.4.6': True,
                                                        '6.4.7': True,
                                                        '6.4.8': True,
                                                        '6.4.9': True,
                                                        '6.4.10': True,
                                                        '6.4.11': True,
                                                        '7.0.1': True,
                                                        '7.0.2': True,
                                                        '7.0.3': True,
                                                        '7.0.4': True,
                                                        '7.0.5': True,
                                                        '7.0.6': True,
                                                        '7.0.7': True,
                                                        '7.2.1': True,
                                                        '7.2.2': True,
                                                        '7.4.0': True
                                                    },
                                                    'type': 'int'
                                                },
                                                'preempt': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True,
                                                        '6.2.0': False,
                                                        '6.2.2': False,
                                                        '6.2.6': False,
                                                        '6.2.7': False,
                                                        '6.2.8': True,
                                                        '6.2.9': True,
                                                        '6.2.10': True,
                                                        '6.4.1': False,
                                                        '6.4.3': False,
                                                        '6.4.4': False,
                                                        '6.4.6': True,
                                                        '6.4.7': True,
                                                        '6.4.8': True,
                                                        '6.4.9': True,
                                                        '6.4.10': True,
                                                        '6.4.11': True,
                                                        '7.0.1': True,
                                                        '7.0.2': True,
                                                        '7.0.3': True,
                                                        '7.0.4': True,
                                                        '7.0.5': True,
                                                        '7.0.6': True,
                                                        '7.0.7': True,
                                                        '7.2.1': True,
                                                        '7.2.2': True,
                                                        '7.4.0': True
                                                    },
                                                    'choices': [
                                                        'disable',
                                                        'enable'
                                                    ],
                                                    'type': 'str'
                                                },
                                                'priority': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True,
                                                        '6.2.0': False,
                                                        '6.2.2': False,
                                                        '6.2.6': False,
                                                        '6.2.7': False,
                                                        '6.2.8': True,
                                                        '6.2.9': True,
                                                        '6.2.10': True,
                                                        '6.4.1': False,
                                                        '6.4.3': False,
                                                        '6.4.4': False,
                                                        '6.4.6': True,
                                                        '6.4.7': True,
                                                        '6.4.8': True,
                                                        '6.4.9': True,
                                                        '6.4.10': True,
                                                        '6.4.11': True,
                                                        '7.0.1': True,
                                                        '7.0.2': True,
                                                        '7.0.3': True,
                                                        '7.0.4': True,
                                                        '7.0.5': True,
                                                        '7.0.6': True,
                                                        '7.0.7': True,
                                                        '7.2.1': True,
                                                        '7.2.2': True,
                                                        '7.4.0': True
                                                    },
                                                    'type': 'int'
                                                },
                                                'start-time': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True,
                                                        '6.2.0': False,
                                                        '6.2.2': False,
                                                        '6.2.6': False,
                                                        '6.2.7': False,
                                                        '6.2.8': True,
                                                        '6.2.9': True,
                                                        '6.2.10': True,
                                                        '6.4.1': False,
                                                        '6.4.3': False,
                                                        '6.4.4': False,
                                                        '6.4.6': True,
                                                        '6.4.7': True,
                                                        '6.4.8': True,
                                                        '6.4.9': True,
                                                        '6.4.10': True,
                                                        '6.4.11': True,
                                                        '7.0.1': True,
                                                        '7.0.2': True,
                                                        '7.0.3': True,
                                                        '7.0.4': True,
                                                        '7.0.5': True,
                                                        '7.0.6': True,
                                                        '7.0.7': True,
                                                        '7.2.1': True,
                                                        '7.2.2': True,
                                                        '7.4.0': True
                                                    },
                                                    'type': 'int'
                                                },
                                                'status': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True,
                                                        '6.2.0': False,
                                                        '6.2.2': False,
                                                        '6.2.6': False,
                                                        '6.2.7': False,
                                                        '6.2.8': True,
                                                        '6.2.9': True,
                                                        '6.2.10': True,
                                                        '6.4.1': False,
                                                        '6.4.3': False,
                                                        '6.4.4': False,
                                                        '6.4.6': True,
                                                        '6.4.7': True,
                                                        '6.4.8': True,
                                                        '6.4.9': True,
                                                        '6.4.10': True,
                                                        '6.4.11': True,
                                                        '7.0.1': True,
                                                        '7.0.2': True,
                                                        '7.0.3': True,
                                                        '7.0.4': True,
                                                        '7.0.5': True,
                                                        '7.0.6': True,
                                                        '7.0.7': True,
                                                        '7.2.1': True,
                                                        '7.2.2': True,
                                                        '7.4.0': True
                                                    },
                                                    'choices': [
                                                        'disable',
                                                        'enable'
                                                    ],
                                                    'type': 'str'
                                                },
                                                'vrdst6': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True,
                                                        '6.2.0': False,
                                                        '6.2.2': False,
                                                        '6.2.6': False,
                                                        '6.2.7': False,
                                                        '6.2.8': True,
                                                        '6.2.9': True,
                                                        '6.2.10': True,
                                                        '6.4.1': False,
                                                        '6.4.3': False,
                                                        '6.4.4': False,
                                                        '6.4.6': True,
                                                        '6.4.7': True,
                                                        '6.4.8': True,
                                                        '6.4.9': True,
                                                        '6.4.10': True,
                                                        '6.4.11': True,
                                                        '7.0.1': True,
                                                        '7.0.2': True,
                                                        '7.0.3': True,
                                                        '7.0.4': True,
                                                        '7.0.5': True,
                                                        '7.0.6': True,
                                                        '7.0.7': True,
                                                        '7.2.1': True,
                                                        '7.2.2': True,
                                                        '7.4.0': True
                                                    },
                                                    'type': 'str'
                                                },
                                                'vrgrp': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True,
                                                        '6.2.0': False,
                                                        '6.2.2': False,
                                                        '6.2.6': False,
                                                        '6.2.7': False,
                                                        '6.2.8': True,
                                                        '6.2.9': True,
                                                        '6.2.10': True,
                                                        '6.4.1': False,
                                                        '6.4.3': False,
                                                        '6.4.4': False,
                                                        '6.4.6': True,
                                                        '6.4.7': True,
                                                        '6.4.8': True,
                                                        '6.4.9': True,
                                                        '6.4.10': True,
                                                        '6.4.11': True,
                                                        '7.0.1': True,
                                                        '7.0.2': True,
                                                        '7.0.3': True,
                                                        '7.0.4': True,
                                                        '7.0.5': True,
                                                        '7.0.6': True,
                                                        '7.0.7': True,
                                                        '7.2.1': True,
                                                        '7.2.2': True,
                                                        '7.4.0': True
                                                    },
                                                    'type': 'int'
                                                },
                                                'vrid': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True,
                                                        '6.2.0': False,
                                                        '6.2.2': False,
                                                        '6.2.6': False,
                                                        '6.2.7': False,
                                                        '6.2.8': True,
                                                        '6.2.9': True,
                                                        '6.2.10': True,
                                                        '6.4.1': False,
                                                        '6.4.3': False,
                                                        '6.4.4': False,
                                                        '6.4.6': True,
                                                        '6.4.7': True,
                                                        '6.4.8': True,
                                                        '6.4.9': True,
                                                        '6.4.10': True,
                                                        '6.4.11': True,
                                                        '7.0.1': True,
                                                        '7.0.2': True,
                                                        '7.0.3': True,
                                                        '7.0.4': True,
                                                        '7.0.5': True,
                                                        '7.0.6': True,
                                                        '7.0.7': True,
                                                        '7.2.1': True,
                                                        '7.2.2': True,
                                                        '7.4.0': True
                                                    },
                                                    'type': 'int'
                                                },
                                                'vrip6': {
                                                    'required': False,
                                                    'revision': {
                                                        '6.4.5': True,
                                                        '7.0.0': True,
                                                        '7.2.0': True,
                                                        '6.2.0': False,
                                                        '6.2.2': False,
                                                        '6.2.6': False,
                                                        '6.2.7': False,
                                                        '6.2.8': True,
                                                        '6.2.9': True,
                                                        '6.2.10': True,
                                                        '6.4.1': False,
                                                        '6.4.3': False,
                                                        '6.4.4': False,
                                                        '6.4.6': True,
                                                        '6.4.7': True,
                                                        '6.4.8': True,
                                                        '6.4.9': True,
                                                        '6.4.10': True,
                                                        '6.4.11': True,
                                                        '7.0.1': True,
                                                        '7.0.2': True,
                                                        '7.0.3': True,
                                                        '7.0.4': True,
                                                        '7.0.5': True,
                                                        '7.0.6': True,
                                                        '7.0.7': True,
                                                        '7.2.1': True,
                                                        '7.2.2': True,
                                                        '7.4.0': True
                                                    },
                                                    'type': 'str'
                                                }
                                            },
                                            'elements': 'dict'
                                        },
                                        'cli-conn6-status': {
                                            'required': False,
                                            'revision': {
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': False,
                                                '6.2.9': False,
                                                '6.2.10': False,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': False,
                                                '6.4.7': False,
                                                '6.4.8': False,
                                                '6.4.9': False,
                                                '6.4.10': False,
                                                '6.4.11': False,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'ip6-prefix-mode': {
                                            'required': False,
                                            'revision': {
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': False,
                                                '6.2.9': False,
                                                '6.2.10': False,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': False,
                                                '6.4.7': False,
                                                '6.4.8': False,
                                                '6.4.9': False,
                                                '6.4.10': False,
                                                '6.4.11': False,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'choices': [
                                                'dhcp6',
                                                'ra'
                                            ],
                                            'type': 'str'
                                        },
                                        'ra-send-mtu': {
                                            'required': False,
                                            'revision': {
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': False,
                                                '6.2.9': False,
                                                '6.2.10': False,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'choices': [
                                                'disable',
                                                'enable'
                                            ],
                                            'type': 'str'
                                        },
                                        'ip6-delegated-prefix-iaid': {
                                            'required': False,
                                            'revision': {
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': False,
                                                '6.2.9': False,
                                                '6.2.10': False,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': False,
                                                '6.4.7': False,
                                                '6.4.8': False,
                                                '6.4.9': False,
                                                '6.4.10': False,
                                                '6.4.11': False,
                                                '7.0.1': False,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'dhcp6-relay-source-interface': {
                                            'required': False,
                                            'revision': {
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'choices': [
                                                'disable',
                                                'enable'
                                            ],
                                            'type': 'str'
                                        }
                                    }
                                },
                                'secondary-IP': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'secondaryip': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'list',
                                    'options': {
                                        'allowaccess': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'list',
                                            'choices': [
                                                'https',
                                                'ping',
                                                'ssh',
                                                'snmp',
                                                'http',
                                                'telnet',
                                                'fgfm',
                                                'auto-ipsec',
                                                'radius-acct',
                                                'probe-response',
                                                'capwap',
                                                'dnp',
                                                'ftm',
                                                'fabric',
                                                'speed-test'
                                            ],
                                            'elements': 'str'
                                        },
                                        'detectprotocol': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': False,
                                                '7.2.2': False,
                                                '7.4.0': False
                                            },
                                            'type': 'list',
                                            'choices': [
                                                'ping',
                                                'tcp-echo',
                                                'udp-echo'
                                            ],
                                            'elements': 'str'
                                        },
                                        'detectserver': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': False,
                                                '7.2.2': False,
                                                '7.4.0': False
                                            },
                                            'type': 'str'
                                        },
                                        'gwdetect': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': False,
                                                '7.2.2': False,
                                                '7.4.0': False
                                            },
                                            'choices': [
                                                'disable',
                                                'enable'
                                            ],
                                            'type': 'str'
                                        },
                                        'ha-priority': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': False,
                                                '7.2.2': False,
                                                '7.4.0': False
                                            },
                                            'type': 'int'
                                        },
                                        'id': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'ip': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'ping-serv-status': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': False,
                                                '7.2.2': False,
                                                '7.4.0': False
                                            },
                                            'type': 'int'
                                        },
                                        'seq': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True,
                                                '6.2.0': False,
                                                '6.2.2': False,
                                                '6.2.6': False,
                                                '6.2.7': False,
                                                '6.2.8': True,
                                                '6.2.9': True,
                                                '6.2.10': True,
                                                '6.4.1': False,
                                                '6.4.3': False,
                                                '6.4.4': False,
                                                '6.4.6': True,
                                                '6.4.7': True,
                                                '6.4.8': True,
                                                '6.4.9': True,
                                                '6.4.10': True,
                                                '6.4.11': True,
                                                '7.0.1': True,
                                                '7.0.2': True,
                                                '7.0.3': True,
                                                '7.0.4': True,
                                                '7.0.5': True,
                                                '7.0.6': True,
                                                '7.0.7': True,
                                                '7.2.1': True,
                                                '7.2.2': True,
                                                '7.4.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'secip-relay-ip': {
                                            'required': False,
                                            'revision': {
                                                '7.4.0': True
                                            },
                                            'type': 'str'
                                        }
                                    },
                                    'elements': 'dict'
                                },
                                'vlanid': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'int'
                                },
                                'dhcp-relay-interface-select-method': {
                                    'required': False,
                                    'revision': {
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': False,
                                        '6.2.9': False,
                                        '6.2.10': False,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': False,
                                        '6.4.7': False,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': False,
                                        '7.0.2': False,
                                        '7.0.3': False,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'choices': [
                                        'auto',
                                        'sdwan',
                                        'specify'
                                    ],
                                    'type': 'str'
                                },
                                'vrrp': {
                                    'required': False,
                                    'revision': {
                                        '7.4.0': True
                                    },
                                    'type': 'list',
                                    'options': {
                                        'accept-mode': {
                                            'required': False,
                                            'revision': {
                                                '7.4.0': True
                                            },
                                            'choices': [
                                                'disable',
                                                'enable'
                                            ],
                                            'type': 'str'
                                        },
                                        'adv-interval': {
                                            'required': False,
                                            'revision': {
                                                '7.4.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'ignore-default-route': {
                                            'required': False,
                                            'revision': {
                                                '7.4.0': True
                                            },
                                            'choices': [
                                                'disable',
                                                'enable'
                                            ],
                                            'type': 'str'
                                        },
                                        'preempt': {
                                            'required': False,
                                            'revision': {
                                                '7.4.0': True
                                            },
                                            'choices': [
                                                'disable',
                                                'enable'
                                            ],
                                            'type': 'str'
                                        },
                                        'priority': {
                                            'required': False,
                                            'revision': {
                                                '7.4.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'proxy-arp': {
                                            'required': False,
                                            'revision': {
                                                '7.4.0': True
                                            },
                                            'type': 'list',
                                            'options': {
                                                'id': {
                                                    'required': False,
                                                    'revision': {
                                                        '7.4.0': True
                                                    },
                                                    'type': 'int'
                                                },
                                                'ip': {
                                                    'required': False,
                                                    'revision': {
                                                        '7.4.0': True
                                                    },
                                                    'type': 'str'
                                                }
                                            },
                                            'elements': 'dict'
                                        },
                                        'start-time': {
                                            'required': False,
                                            'revision': {
                                                '7.4.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'status': {
                                            'required': False,
                                            'revision': {
                                                '7.4.0': True
                                            },
                                            'choices': [
                                                'disable',
                                                'enable'
                                            ],
                                            'type': 'str'
                                        },
                                        'version': {
                                            'required': False,
                                            'revision': {
                                                '7.4.0': True
                                            },
                                            'choices': [
                                                '2',
                                                '3'
                                            ],
                                            'type': 'str'
                                        },
                                        'vrdst': {
                                            'required': False,
                                            'revision': {
                                                '7.4.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'vrdst-priority': {
                                            'required': False,
                                            'revision': {
                                                '7.4.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'vrgrp': {
                                            'required': False,
                                            'revision': {
                                                '7.4.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'vrid': {
                                            'required': False,
                                            'revision': {
                                                '7.4.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'vrip': {
                                            'required': False,
                                            'revision': {
                                                '7.4.0': True
                                            },
                                            'type': 'str'
                                        }
                                    },
                                    'elements': 'dict'
                                }
                            }
                        }
                    },
                    'elements': 'dict'
                },
                'name': {
                    'required': True,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'portal-message-override-group': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': False,
                        '6.2.5': False,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False,
                        '6.2.0': True,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.4.1': False,
                        '6.4.3': False,
                        '6.4.4': False,
                        '6.4.6': False,
                        '6.4.7': False,
                        '6.4.8': False,
                        '6.4.9': False,
                        '6.4.10': False,
                        '6.4.11': False,
                        '7.0.1': False,
                        '7.0.2': False,
                        '7.0.3': False,
                        '7.0.4': False,
                        '7.0.5': False,
                        '7.0.6': False,
                        '7.0.7': False,
                        '7.2.1': False,
                        '7.2.2': False,
                        '7.4.0': False
                    },
                    'type': 'str'
                },
                'radius-server': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': False,
                        '6.2.5': False,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False,
                        '6.2.0': True,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.4.1': False,
                        '6.4.3': False,
                        '6.4.4': False,
                        '6.4.6': False,
                        '6.4.7': False,
                        '6.4.8': False,
                        '6.4.9': False,
                        '6.4.10': False,
                        '6.4.11': False,
                        '7.0.1': False,
                        '7.0.2': False,
                        '7.0.3': False,
                        '7.0.4': False,
                        '7.0.5': False,
                        '7.0.6': False,
                        '7.0.7': False,
                        '7.2.1': False,
                        '7.2.2': False,
                        '7.4.0': False
                    },
                    'type': 'str'
                },
                'security': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': False,
                        '6.2.5': False,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False,
                        '6.2.0': True,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.4.1': False,
                        '6.4.3': False,
                        '6.4.4': False,
                        '6.4.6': False,
                        '6.4.7': False,
                        '6.4.8': False,
                        '6.4.9': False,
                        '6.4.10': False,
                        '6.4.11': False,
                        '7.0.1': False,
                        '7.0.2': False,
                        '7.0.3': False,
                        '7.0.4': False,
                        '7.0.5': False,
                        '7.0.6': False,
                        '7.0.7': False,
                        '7.2.1': False,
                        '7.2.2': False,
                        '7.4.0': False
                    },
                    'choices': [
                        'open',
                        'captive-portal',
                        '8021x'
                    ],
                    'type': 'str'
                },
                'selected-usergroups': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': False,
                        '6.2.5': False,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False,
                        '6.2.0': True,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.4.1': False,
                        '6.4.3': False,
                        '6.4.4': False,
                        '6.4.6': False,
                        '6.4.7': False,
                        '6.4.8': False,
                        '6.4.9': False,
                        '6.4.10': False,
                        '6.4.11': False,
                        '7.0.1': False,
                        '7.0.2': False,
                        '7.0.3': False,
                        '7.0.4': False,
                        '7.0.5': False,
                        '7.0.6': False,
                        '7.0.7': False,
                        '7.2.1': False,
                        '7.2.2': False,
                        '7.4.0': False
                    },
                    'type': 'str'
                },
                'usergroup': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': False,
                        '6.2.5': False,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False,
                        '6.2.0': True,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.4.1': False,
                        '6.4.3': False,
                        '6.4.4': False,
                        '6.4.6': False,
                        '6.4.7': False,
                        '6.4.8': False,
                        '6.4.9': False,
                        '6.4.10': False,
                        '6.4.11': False,
                        '7.0.1': False,
                        '7.0.2': False,
                        '7.0.3': False,
                        '7.0.4': False,
                        '7.0.5': False,
                        '7.0.6': False,
                        '7.0.7': False,
                        '7.2.1': False,
                        '7.2.2': False,
                        '7.4.0': False
                    },
                    'type': 'str'
                },
                'vdom': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'vlanid': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'dhcp-server': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'auto-configuration': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'auto-managed-status': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'conflicted-ip-timeout': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'int'
                        },
                        'ddns-auth': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'tsig'
                            ],
                            'type': 'str'
                        },
                        'ddns-key': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'ddns-keyname': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'ddns-server-ip': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'ddns-ttl': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'int'
                        },
                        'ddns-update': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'ddns-update-override': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'ddns-zone': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'default-gateway': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'dhcp-settings-from-fortiipam': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'dns-server1': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'dns-server2': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'dns-server3': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'dns-server4': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'dns-service': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'default',
                                'specify',
                                'local'
                            ],
                            'type': 'str'
                        },
                        'domain': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'enable': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'exclude-range': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'list',
                            'options': {
                                'end-ip': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'id': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'int'
                                },
                                'start-ip': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'vci-match': {
                                    'required': False,
                                    'revision': {
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'vci-string': {
                                    'required': False,
                                    'revision': {
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'lease-time': {
                                    'required': False,
                                    'revision': {
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'int'
                                },
                                'uci-match': {
                                    'required': False,
                                    'revision': {
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'uci-string': {
                                    'required': False,
                                    'revision': {
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                }
                            },
                            'elements': 'dict'
                        },
                        'filename': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'forticlient-on-net-status': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'int'
                        },
                        'ip-mode': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'range',
                                'usrgrp'
                            ],
                            'type': 'str'
                        },
                        'ip-range': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'list',
                            'options': {
                                'end-ip': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'id': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'int'
                                },
                                'start-ip': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'vci-match': {
                                    'required': False,
                                    'revision': {
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'vci-string': {
                                    'required': False,
                                    'revision': {
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'lease-time': {
                                    'required': False,
                                    'revision': {
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'int'
                                },
                                'uci-match': {
                                    'required': False,
                                    'revision': {
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'uci-string': {
                                    'required': False,
                                    'revision': {
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                }
                            },
                            'elements': 'dict'
                        },
                        'ipsec-lease-hold': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'int'
                        },
                        'lease-time': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'int'
                        },
                        'mac-acl-default-action': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'assign',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'netmask': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'next-server': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'ntp-server1': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'ntp-server2': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'ntp-server3': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'ntp-service': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'default',
                                'specify',
                                'local'
                            ],
                            'type': 'str'
                        },
                        'option1': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'option2': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'option3': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'option4': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'option5': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'option6': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'list',
                            'options': {
                                'code': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'int'
                                },
                                'id': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'int'
                                },
                                'ip': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'type': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'choices': [
                                        'hex',
                                        'string',
                                        'ip',
                                        'fqdn'
                                    ],
                                    'type': 'str'
                                },
                                'value': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'vci-match': {
                                    'required': False,
                                    'revision': {
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'vci-string': {
                                    'required': False,
                                    'revision': {
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'uci-match': {
                                    'required': False,
                                    'revision': {
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'uci-string': {
                                    'required': False,
                                    'revision': {
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                }
                            },
                            'elements': 'dict'
                        },
                        'reserved-address': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'list',
                            'options': {
                                'action': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'choices': [
                                        'assign',
                                        'block',
                                        'reserved'
                                    ],
                                    'type': 'str'
                                },
                                'circuit-id': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'circuit-id-type': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'choices': [
                                        'hex',
                                        'string'
                                    ],
                                    'type': 'str'
                                },
                                'description': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'id': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'int'
                                },
                                'ip': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'mac': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'remote-id': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'remote-id-type': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'choices': [
                                        'hex',
                                        'string'
                                    ],
                                    'type': 'str'
                                },
                                'type': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.4.0': True
                                    },
                                    'choices': [
                                        'mac',
                                        'option82'
                                    ],
                                    'type': 'str'
                                }
                            },
                            'elements': 'dict'
                        },
                        'server-type': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'regular',
                                'ipsec'
                            ],
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'tftp-server': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'timezone': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                '00',
                                '01',
                                '02',
                                '03',
                                '04',
                                '05',
                                '06',
                                '07',
                                '08',
                                '09',
                                '10',
                                '11',
                                '12',
                                '13',
                                '14',
                                '15',
                                '16',
                                '17',
                                '18',
                                '19',
                                '20',
                                '21',
                                '22',
                                '23',
                                '24',
                                '25',
                                '26',
                                '27',
                                '28',
                                '29',
                                '30',
                                '31',
                                '32',
                                '33',
                                '34',
                                '35',
                                '36',
                                '37',
                                '38',
                                '39',
                                '40',
                                '41',
                                '42',
                                '43',
                                '44',
                                '45',
                                '46',
                                '47',
                                '48',
                                '49',
                                '50',
                                '51',
                                '52',
                                '53',
                                '54',
                                '55',
                                '56',
                                '57',
                                '58',
                                '59',
                                '60',
                                '61',
                                '62',
                                '63',
                                '64',
                                '65',
                                '66',
                                '67',
                                '68',
                                '69',
                                '70',
                                '71',
                                '72',
                                '73',
                                '74',
                                '75',
                                '76',
                                '77',
                                '78',
                                '79',
                                '80',
                                '81',
                                '82',
                                '83',
                                '84',
                                '85',
                                '86',
                                '87'
                            ],
                            'type': 'str'
                        },
                        'timezone-option': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'default',
                                'specify'
                            ],
                            'type': 'str'
                        },
                        'vci-match': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'vci-string': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'wifi-ac-service': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'specify',
                                'local'
                            ],
                            'type': 'str'
                        },
                        'wifi-ac1': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'wifi-ac2': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'wifi-ac3': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'wins-server1': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'wins-server2': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'relay-agent': {
                            'required': False,
                            'revision': {
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'shared-subnet': {
                            'required': False,
                            'revision': {
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'interface': {
                    'required': False,
                    'type': 'dict'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'fsp_vlan'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('access_token', module.params['access_token'] if 'access_token' in module.params else None)
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        connection.set_option('forticloud_access_token',
                              module.params['forticloud_access_token'] if 'forticloud_access_token' in module.params else None)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_curd(argument_specs=module_arg_spec)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()

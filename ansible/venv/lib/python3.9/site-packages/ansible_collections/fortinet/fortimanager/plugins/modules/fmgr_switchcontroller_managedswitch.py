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
module: fmgr_switchcontroller_managedswitch
short_description: Configure FortiSwitch devices that are managed by this FortiGate.
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
    switchcontroller_managedswitch:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            _platform:
                type: str
                description: _Platform.
            description:
                type: str
                description: Description.
            name:
                type: str
                description: Managed-switch name.
            ports:
                description: Ports.
                type: list
                elements: dict
                suboptions:
                    allowed-vlans:
                        type: str
                        description: Configure switch port tagged vlans
                    allowed-vlans-all:
                        type: str
                        description: Enable/disable all defined vlans on this port.
                        choices:
                            - 'disable'
                            - 'enable'
                    arp-inspection-trust:
                        type: str
                        description: Trusted or untrusted dynamic ARP inspection.
                        choices:
                            - 'untrusted'
                            - 'trusted'
                    bundle:
                        type: str
                        description: Enable/disable Link Aggregation Group
                        choices:
                            - 'disable'
                            - 'enable'
                    description:
                        type: str
                        description: Description for port.
                    dhcp-snoop-option82-trust:
                        type: str
                        description: Enable/disable allowance of DHCP with option-82 on untrusted interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    dhcp-snooping:
                        type: str
                        description: Trusted or untrusted DHCP-snooping interface.
                        choices:
                            - 'trusted'
                            - 'untrusted'
                    discard-mode:
                        type: str
                        description: Configure discard mode for port.
                        choices:
                            - 'none'
                            - 'all-untagged'
                            - 'all-tagged'
                    edge-port:
                        type: str
                        description: Enable/disable this interface as an edge port, bridging connections between workstations and/or computers.
                        choices:
                            - 'disable'
                            - 'enable'
                    igmp-snooping:
                        type: str
                        description: Set IGMP snooping mode for the physical port interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    igmps-flood-reports:
                        type: str
                        description: Enable/disable flooding of IGMP reports to this interface when igmp-snooping enabled.
                        choices:
                            - 'disable'
                            - 'enable'
                    igmps-flood-traffic:
                        type: str
                        description: Enable/disable flooding of IGMP snooping traffic to this interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    lacp-speed:
                        type: str
                        description: end Link Aggregation Control Protocol
                        choices:
                            - 'slow'
                            - 'fast'
                    learning-limit:
                        type: int
                        description: Limit the number of dynamic MAC addresses on this Port
                    lldp-profile:
                        type: str
                        description: LLDP port TLV profile.
                    lldp-status:
                        type: str
                        description: LLDP transmit and receive status.
                        choices:
                            - 'disable'
                            - 'rx-only'
                            - 'tx-only'
                            - 'tx-rx'
                    loop-guard:
                        type: str
                        description: Enable/disable loop-guard on this interface, an STP optimization used to prevent network loops.
                        choices:
                            - 'disabled'
                            - 'enabled'
                    loop-guard-timeout:
                        type: int
                        description: Loop-guard timeout
                    max-bundle:
                        type: int
                        description: Maximum size of LAG bundle
                    mclag:
                        type: str
                        description: Enable/disable multi-chassis link aggregation
                        choices:
                            - 'disable'
                            - 'enable'
                    member-withdrawal-behavior:
                        type: str
                        description: Port behavior after it withdraws because of loss of control packets.
                        choices:
                            - 'forward'
                            - 'block'
                    members:
                        description: Aggregated LAG bundle interfaces.
                        type: str
                    min-bundle:
                        type: int
                        description: Minimum size of LAG bundle
                    mode:
                        type: str
                        description: LACP mode
                        choices:
                            - 'static'
                            - 'lacp-passive'
                            - 'lacp-active'
                    poe-pre-standard-detection:
                        type: str
                        description: Enable/disable PoE pre-standard detection.
                        choices:
                            - 'disable'
                            - 'enable'
                    poe-status:
                        type: str
                        description: Enable/disable PoE status.
                        choices:
                            - 'disable'
                            - 'enable'
                    port-name:
                        type: str
                        description: Switch port name.
                    port-owner:
                        type: str
                        description: Switch port name.
                    port-security-policy:
                        type: str
                        description: Switch controller authentication policy to apply to this managed switch from available options.
                    port-selection-criteria:
                        type: str
                        description: Algorithm for aggregate port selection.
                        choices:
                            - 'src-mac'
                            - 'dst-mac'
                            - 'src-dst-mac'
                            - 'src-ip'
                            - 'dst-ip'
                            - 'src-dst-ip'
                    qos-policy:
                        type: str
                        description: Switch controller QoS policy from available options.
                    sample-direction:
                        type: str
                        description: sFlow sample direction.
                        choices:
                            - 'rx'
                            - 'tx'
                            - 'both'
                    sflow-counter-interval:
                        type: int
                        description: sFlow sampler counter polling interval
                    sflow-sample-rate:
                        type: int
                        description: sFlow sampler sample rate
                    sflow-sampler:
                        type: str
                        description: Enable/disable sFlow protocol on this interface.
                        choices:
                            - 'disabled'
                            - 'enabled'
                    stp-bpdu-guard:
                        type: str
                        description: Enable/disable STP BPDU guard on this interface.
                        choices:
                            - 'disabled'
                            - 'enabled'
                    stp-bpdu-guard-timeout:
                        type: int
                        description: BPDU Guard disabling protection
                    stp-root-guard:
                        type: str
                        description: Enable/disable STP root guard on this interface.
                        choices:
                            - 'disabled'
                            - 'enabled'
                    stp-state:
                        type: str
                        description: Enable/disable Spanning Tree Protocol
                        choices:
                            - 'disabled'
                            - 'enabled'
                    type:
                        type: str
                        description: Interface type
                        choices:
                            - 'physical'
                            - 'trunk'
                    untagged-vlans:
                        type: str
                        description: Configure switch port untagged vlans
                    vlan:
                        type: str
                        description: Assign switch ports to a VLAN.
                    export-to-pool-flag:
                        type: int
                        description: Switch controller export port to pool-list.
                    mac-addr:
                        type: str
                        description: Port/Trunk MAC.
                    packet-sample-rate:
                        type: int
                        description: Packet sampling rate
                    packet-sampler:
                        type: str
                        description: Enable/disable packet sampling on this interface.
                        choices:
                            - 'disabled'
                            - 'enabled'
                    sticky-mac:
                        type: str
                        description: Enable or disable sticky-mac on the interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    storm-control-policy:
                        type: str
                        description: Switch controller storm control policy from available options.
                    max-miss-heartbeats:
                        type: int
                        description: Maximum tolerant missed heartbeats.
                    dot1x-enable:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    access-mode:
                        type: str
                        description: Access mode of the port.
                        choices:
                            - 'normal'
                            - 'nac'
                            - 'dynamic'
                            - 'static'
                    ip-source-guard:
                        type: str
                        description: Enable/disable IP source guard.
                        choices:
                            - 'disable'
                            - 'enable'
                    mclag-icl-port:
                        type: int
                        description: Mclag-Icl-Port.
                    p2p-port:
                        type: int
                        description: P2P-Port.
                    aggregator-mode:
                        type: str
                        description: LACP member select mode.
                        choices:
                            - 'bandwidth'
                            - 'count'
                    rpvst-port:
                        type: str
                        description: Enable/disable inter-operability with rapid PVST on this interface.
                        choices:
                            - 'disabled'
                            - 'enabled'
                    flow-control:
                        type: str
                        description: Flow control direction.
                        choices:
                            - 'disable'
                            - 'tx'
                            - 'rx'
                            - 'both'
                    media-type:
                        type: str
                        description: Media-Type.
                    pause-meter:
                        type: int
                        description: Configure ingress pause metering rate, in kbps
                    pause-meter-resume:
                        type: str
                        description: Resume threshold for resuming traffic on ingress port.
                        choices:
                            - '25%'
                            - '50%'
                            - '75%'
                    trunk-member:
                        type: int
                        description: Trunk member.
                    fec-capable:
                        type: int
                        description: FEC capable.
                    fec-state:
                        type: str
                        description: State of forward error correction.
                        choices:
                            - 'disabled'
                            - 'cl74'
                            - 'cl91'
                    matched-dpp-intf-tags:
                        type: str
                        description: Matched interface tags in the dynamic port policy.
                    matched-dpp-policy:
                        type: str
                        description: Matched child policy in the dynamic port policy.
                    port-policy:
                        type: str
                        description: Switch controller dynamic port policy from available options.
                    status:
                        type: str
                        description: Switch port admin status
                        choices:
                            - 'down'
                            - 'up'
                    dsl-profile:
                        type: str
                        description: DSL policy configuration.
                    flap-duration:
                        type: int
                        description: Period over which flap events are calculated
                    flap-rate:
                        type: int
                        description: Number of stage change events needed within flap-duration.
                    flap-timeout:
                        type: int
                        description: Flap guard disabling protection
                    flapguard:
                        type: str
                        description: Enable/disable flap guard.
                        choices:
                            - 'disable'
                            - 'enable'
                    interface-tags:
                        description: description
                        type: str
                    poe-max-power:
                        type: str
                        description: no description
                    poe-standard:
                        type: str
                        description: no description
                    igmp-snooping-flood-reports:
                        type: str
                        description: Enable/disable flooding of IGMP reports to this interface when igmp-snooping enabled.
                        choices:
                            - 'disable'
                            - 'enable'
                    mcast-snooping-flood-traffic:
                        type: str
                        description: Enable/disable flooding of IGMP snooping traffic to this interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    link-status:
                        type: str
                        description: no description
                        choices:
                            - 'down'
                            - 'up'
                    poe-mode-bt-cabable:
                        type: int
                        description: PoE mode IEEE 802.
                    poe-port-mode:
                        type: str
                        description: Configure PoE port mode.
                        choices:
                            - 'ieee802-3af'
                            - 'ieee802-3at'
                            - 'ieee802-3bt'
                    poe-port-power:
                        type: str
                        description: Configure PoE port power.
                        choices:
                            - 'normal'
                            - 'perpetual'
                            - 'perpetual-fast'
                    poe-port-priority:
                        type: str
                        description: Configure PoE port priority.
                        choices:
                            - 'critical-priority'
                            - 'high-priority'
                            - 'low-priority'
                            - 'medium-priority'
                    acl-group:
                        description: description
                        type: str
                    dhcp-snoop-option82-override:
                        description: description
                        type: list
                        elements: dict
                        suboptions:
                            circuit-id:
                                type: str
                                description: Circuit ID string.
                            remote-id:
                                type: str
                                description: Remote ID string.
                            vlan-name:
                                type: str
                                description: DHCP snooping option 82 VLAN.
                    fortiswitch-acls:
                        description: description
                        type: int
                    isl-peer-device-sn:
                        type: str
                        description: no description
            switch-id:
                type: str
                description: Managed-switch id.
            override-snmp-community:
                type: str
                description: Enable/disable overriding the global SNMP communities.
                choices:
                    - 'disable'
                    - 'enable'
            override-snmp-sysinfo:
                type: str
                description: Enable/disable overriding the global SNMP system information.
                choices:
                    - 'disable'
                    - 'enable'
            override-snmp-trap-threshold:
                type: str
                description: Enable/disable overriding the global SNMP trap threshold values.
                choices:
                    - 'disable'
                    - 'enable'
            override-snmp-user:
                type: str
                description: Enable/disable overriding the global SNMP users.
                choices:
                    - 'disable'
                    - 'enable'
            poe-detection-type:
                type: int
                description: Poe-Detection-Type.
            remote-log:
                description: description
                type: list
                elements: dict
                suboptions:
                    csv:
                        type: str
                        description: Enable/disable comma-separated value
                        choices:
                            - 'disable'
                            - 'enable'
                    facility:
                        type: str
                        description: Facility to log to remote syslog server.
                        choices:
                            - 'kernel'
                            - 'user'
                            - 'mail'
                            - 'daemon'
                            - 'auth'
                            - 'syslog'
                            - 'lpr'
                            - 'news'
                            - 'uucp'
                            - 'cron'
                            - 'authpriv'
                            - 'ftp'
                            - 'ntp'
                            - 'audit'
                            - 'alert'
                            - 'clock'
                            - 'local0'
                            - 'local1'
                            - 'local2'
                            - 'local3'
                            - 'local4'
                            - 'local5'
                            - 'local6'
                            - 'local7'
                    name:
                        type: str
                        description: Remote log name.
                    port:
                        type: int
                        description: Remote syslog server listening port.
                    server:
                        type: str
                        description: IPv4 address of the remote syslog server.
                    severity:
                        type: str
                        description: Severity of logs to be transferred to remote log server.
                        choices:
                            - 'emergency'
                            - 'alert'
                            - 'critical'
                            - 'error'
                            - 'warning'
                            - 'notification'
                            - 'information'
                            - 'debug'
                    status:
                        type: str
                        description: Enable/disable logging by FortiSwitch device to a remote syslog server.
                        choices:
                            - 'disable'
                            - 'enable'
            snmp-community:
                description: description
                type: list
                elements: dict
                suboptions:
                    events:
                        description: description
                        type: list
                        elements: str
                        choices:
                            - 'cpu-high'
                            - 'mem-low'
                            - 'log-full'
                            - 'intf-ip'
                            - 'ent-conf-change'
                    hosts:
                        description: description
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                type: int
                                description: Host entry ID.
                            ip:
                                type: str
                                description: IPv4 address of the SNMP manager
                    id:
                        type: int
                        description: SNMP community ID.
                    name:
                        type: str
                        description: SNMP community name.
                    query-v1-port:
                        type: int
                        description: SNMP v1 query port
                    query-v1-status:
                        type: str
                        description: Enable/disable SNMP v1 queries.
                        choices:
                            - 'disable'
                            - 'enable'
                    query-v2c-port:
                        type: int
                        description: SNMP v2c query port
                    query-v2c-status:
                        type: str
                        description: Enable/disable SNMP v2c queries.
                        choices:
                            - 'disable'
                            - 'enable'
                    status:
                        type: str
                        description: Enable/disable this SNMP community.
                        choices:
                            - 'disable'
                            - 'enable'
                    trap-v1-lport:
                        type: int
                        description: SNMP v2c trap local port
                    trap-v1-rport:
                        type: int
                        description: SNMP v2c trap remote port
                    trap-v1-status:
                        type: str
                        description: Enable/disable SNMP v1 traps.
                        choices:
                            - 'disable'
                            - 'enable'
                    trap-v2c-lport:
                        type: int
                        description: SNMP v2c trap local port
                    trap-v2c-rport:
                        type: int
                        description: SNMP v2c trap remote port
                    trap-v2c-status:
                        type: str
                        description: Enable/disable SNMP v2c traps.
                        choices:
                            - 'disable'
                            - 'enable'
            snmp-user:
                description: description
                type: list
                elements: dict
                suboptions:
                    auth-proto:
                        type: str
                        description: Authentication protocol.
                        choices:
                            - 'md5'
                            - 'sha'
                    auth-pwd:
                        description: description
                        type: str
                    name:
                        type: str
                        description: SNMP user name.
                    priv-proto:
                        type: str
                        description: Privacy
                        choices:
                            - 'des'
                            - 'aes'
                    priv-pwd:
                        description: description
                        type: str
                    queries:
                        type: str
                        description: Enable/disable SNMP queries for this user.
                        choices:
                            - 'disable'
                            - 'enable'
                    query-port:
                        type: int
                        description: SNMPv3 query port
                    security-level:
                        type: str
                        description: Security level for message authentication and encryption.
                        choices:
                            - 'no-auth-no-priv'
                            - 'auth-no-priv'
                            - 'auth-priv'
            mclag-igmp-snooping-aware:
                type: str
                description: Enable/disable MCLAG IGMP-snooping awareness.
                choices:
                    - 'disable'
                    - 'enable'
            ip-source-guard:
                description: description
                type: list
                elements: dict
                suboptions:
                    binding-entry:
                        description: description
                        type: list
                        elements: dict
                        suboptions:
                            entry-name:
                                type: str
                                description: Configure binding pair.
                            ip:
                                type: str
                                description: Source IP for this rule.
                            mac:
                                type: str
                                description: MAC address for this rule.
                    description:
                        type: str
                        description: Description.
                    port:
                        type: str
                        description: Ingress interface to which source guard is bound.
            l3-discovered:
                type: int
                description: L3-Discovered.
            qos-drop-policy:
                type: str
                description: Set QoS drop-policy.
                choices:
                    - 'taildrop'
                    - 'random-early-detection'
            qos-red-probability:
                type: int
                description: Set QoS RED/WRED drop probability.
            switch-dhcp_opt43_key:
                type: str
                description: DHCP option43 key.
            tdr-supported:
                type: str
                description: Tdr-Supported.
            custom-command:
                description: Custom-Command.
                type: list
                elements: dict
                suboptions:
                    command-entry:
                        type: str
                        description: List of FortiSwitch commands.
                    command-name:
                        type: str
                        description: Names of commands to be pushed to this FortiSwitch device, as configured under config switch-controller custom-command.
            firmware-provision:
                type: str
                description: Enable/disable provisioning of firmware to FortiSwitches on join connection.
                choices:
                    - 'disable'
                    - 'enable'
            firmware-provision-version:
                type: str
                description: Firmware version to provision to this FortiSwitch on bootup
            dhcp-server-access-list:
                type: str
                description: DHCP snooping server access list.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'global'
            firmware-provision-latest:
                type: str
                description: Enable/disable one-time automatic provisioning of the latest firmware version.
                choices:
                    - 'disable'
                    - 'once'
            dhcp-snooping-static-client:
                description: description
                type: list
                elements: dict
                suboptions:
                    ip:
                        type: str
                        description: Client static IP address.
                    mac:
                        type: str
                        description: Client MAC address.
                    name:
                        type: str
                        description: Client name.
                    port:
                        type: str
                        description: Interface name.
                    vlan:
                        type: str
                        description: VLAN name.

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
    - name: Configure FortiSwitch devices that are managed by this FortiGate.
      fmgr_switchcontroller_managedswitch:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         state: <value in [present, absent]>
         switchcontroller_managedswitch:
            _platform: <value of string>
            description: <value of string>
            name: <value of string>
            ports:
              -
                  allowed-vlans: <value of string>
                  allowed-vlans-all: <value in [disable, enable]>
                  arp-inspection-trust: <value in [untrusted, trusted]>
                  bundle: <value in [disable, enable]>
                  description: <value of string>
                  dhcp-snoop-option82-trust: <value in [disable, enable]>
                  dhcp-snooping: <value in [trusted, untrusted]>
                  discard-mode: <value in [none, all-untagged, all-tagged]>
                  edge-port: <value in [disable, enable]>
                  igmp-snooping: <value in [disable, enable]>
                  igmps-flood-reports: <value in [disable, enable]>
                  igmps-flood-traffic: <value in [disable, enable]>
                  lacp-speed: <value in [slow, fast]>
                  learning-limit: <value of integer>
                  lldp-profile: <value of string>
                  lldp-status: <value in [disable, rx-only, tx-only, ...]>
                  loop-guard: <value in [disabled, enabled]>
                  loop-guard-timeout: <value of integer>
                  max-bundle: <value of integer>
                  mclag: <value in [disable, enable]>
                  member-withdrawal-behavior: <value in [forward, block]>
                  members: <value of string>
                  min-bundle: <value of integer>
                  mode: <value in [static, lacp-passive, lacp-active]>
                  poe-pre-standard-detection: <value in [disable, enable]>
                  poe-status: <value in [disable, enable]>
                  port-name: <value of string>
                  port-owner: <value of string>
                  port-security-policy: <value of string>
                  port-selection-criteria: <value in [src-mac, dst-mac, src-dst-mac, ...]>
                  qos-policy: <value of string>
                  sample-direction: <value in [rx, tx, both]>
                  sflow-counter-interval: <value of integer>
                  sflow-sample-rate: <value of integer>
                  sflow-sampler: <value in [disabled, enabled]>
                  stp-bpdu-guard: <value in [disabled, enabled]>
                  stp-bpdu-guard-timeout: <value of integer>
                  stp-root-guard: <value in [disabled, enabled]>
                  stp-state: <value in [disabled, enabled]>
                  type: <value in [physical, trunk]>
                  untagged-vlans: <value of string>
                  vlan: <value of string>
                  export-to-pool-flag: <value of integer>
                  mac-addr: <value of string>
                  packet-sample-rate: <value of integer>
                  packet-sampler: <value in [disabled, enabled]>
                  sticky-mac: <value in [disable, enable]>
                  storm-control-policy: <value of string>
                  max-miss-heartbeats: <value of integer>
                  dot1x-enable: <value in [disable, enable]>
                  access-mode: <value in [normal, nac, dynamic, ...]>
                  ip-source-guard: <value in [disable, enable]>
                  mclag-icl-port: <value of integer>
                  p2p-port: <value of integer>
                  aggregator-mode: <value in [bandwidth, count]>
                  rpvst-port: <value in [disabled, enabled]>
                  flow-control: <value in [disable, tx, rx, ...]>
                  media-type: <value of string>
                  pause-meter: <value of integer>
                  pause-meter-resume: <value in [25%, 50%, 75%]>
                  trunk-member: <value of integer>
                  fec-capable: <value of integer>
                  fec-state: <value in [disabled, cl74, cl91]>
                  matched-dpp-intf-tags: <value of string>
                  matched-dpp-policy: <value of string>
                  port-policy: <value of string>
                  status: <value in [down, up]>
                  dsl-profile: <value of string>
                  flap-duration: <value of integer>
                  flap-rate: <value of integer>
                  flap-timeout: <value of integer>
                  flapguard: <value in [disable, enable]>
                  interface-tags: <value of string>
                  poe-max-power: <value of string>
                  poe-standard: <value of string>
                  igmp-snooping-flood-reports: <value in [disable, enable]>
                  mcast-snooping-flood-traffic: <value in [disable, enable]>
                  link-status: <value in [down, up]>
                  poe-mode-bt-cabable: <value of integer>
                  poe-port-mode: <value in [ieee802-3af, ieee802-3at, ieee802-3bt]>
                  poe-port-power: <value in [normal, perpetual, perpetual-fast]>
                  poe-port-priority: <value in [critical-priority, high-priority, low-priority, ...]>
                  acl-group: <value of string>
                  dhcp-snoop-option82-override:
                    -
                        circuit-id: <value of string>
                        remote-id: <value of string>
                        vlan-name: <value of string>
                  fortiswitch-acls: <value of integer>
                  isl-peer-device-sn: <value of string>
            switch-id: <value of string>
            override-snmp-community: <value in [disable, enable]>
            override-snmp-sysinfo: <value in [disable, enable]>
            override-snmp-trap-threshold: <value in [disable, enable]>
            override-snmp-user: <value in [disable, enable]>
            poe-detection-type: <value of integer>
            remote-log:
              -
                  csv: <value in [disable, enable]>
                  facility: <value in [kernel, user, mail, ...]>
                  name: <value of string>
                  port: <value of integer>
                  server: <value of string>
                  severity: <value in [emergency, alert, critical, ...]>
                  status: <value in [disable, enable]>
            snmp-community:
              -
                  events:
                    - cpu-high
                    - mem-low
                    - log-full
                    - intf-ip
                    - ent-conf-change
                  hosts:
                    -
                        id: <value of integer>
                        ip: <value of string>
                  id: <value of integer>
                  name: <value of string>
                  query-v1-port: <value of integer>
                  query-v1-status: <value in [disable, enable]>
                  query-v2c-port: <value of integer>
                  query-v2c-status: <value in [disable, enable]>
                  status: <value in [disable, enable]>
                  trap-v1-lport: <value of integer>
                  trap-v1-rport: <value of integer>
                  trap-v1-status: <value in [disable, enable]>
                  trap-v2c-lport: <value of integer>
                  trap-v2c-rport: <value of integer>
                  trap-v2c-status: <value in [disable, enable]>
            snmp-user:
              -
                  auth-proto: <value in [md5, sha]>
                  auth-pwd: <value of string>
                  name: <value of string>
                  priv-proto: <value in [des, aes]>
                  priv-pwd: <value of string>
                  queries: <value in [disable, enable]>
                  query-port: <value of integer>
                  security-level: <value in [no-auth-no-priv, auth-no-priv, auth-priv]>
            mclag-igmp-snooping-aware: <value in [disable, enable]>
            ip-source-guard:
              -
                  binding-entry:
                    -
                        entry-name: <value of string>
                        ip: <value of string>
                        mac: <value of string>
                  description: <value of string>
                  port: <value of string>
            l3-discovered: <value of integer>
            qos-drop-policy: <value in [taildrop, random-early-detection]>
            qos-red-probability: <value of integer>
            switch-dhcp_opt43_key: <value of string>
            tdr-supported: <value of string>
            custom-command:
              -
                  command-entry: <value of string>
                  command-name: <value of string>
            firmware-provision: <value in [disable, enable]>
            firmware-provision-version: <value of string>
            dhcp-server-access-list: <value in [disable, enable, global]>
            firmware-provision-latest: <value in [disable, once]>
            dhcp-snooping-static-client:
              -
                  ip: <value of string>
                  mac: <value of string>
                  name: <value of string>
                  port: <value of string>
                  vlan: <value of string>

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
        '/pm/config/adom/{adom}/obj/switch-controller/managed-switch',
        '/pm/config/global/obj/switch-controller/managed-switch'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}',
        '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}'
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
        'switchcontroller_managedswitch': {
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
                '_platform': {
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
                'description': {
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
                'ports': {
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
                        'allowed-vlans': {
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
                        'allowed-vlans-all': {
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
                        'arp-inspection-trust': {
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
                                'untrusted',
                                'trusted'
                            ],
                            'type': 'str'
                        },
                        'bundle': {
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
                        'description': {
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
                        'dhcp-snoop-option82-trust': {
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
                        'dhcp-snooping': {
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
                                'trusted',
                                'untrusted'
                            ],
                            'type': 'str'
                        },
                        'discard-mode': {
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
                                'none',
                                'all-untagged',
                                'all-tagged'
                            ],
                            'type': 'str'
                        },
                        'edge-port': {
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
                        'igmp-snooping': {
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
                        'igmps-flood-reports': {
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
                        'igmps-flood-traffic': {
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
                        'lacp-speed': {
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
                                'slow',
                                'fast'
                            ],
                            'type': 'str'
                        },
                        'learning-limit': {
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
                        'lldp-profile': {
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
                        'lldp-status': {
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
                                'rx-only',
                                'tx-only',
                                'tx-rx'
                            ],
                            'type': 'str'
                        },
                        'loop-guard': {
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
                                'disabled',
                                'enabled'
                            ],
                            'type': 'str'
                        },
                        'loop-guard-timeout': {
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
                        'max-bundle': {
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
                        'mclag': {
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
                        'member-withdrawal-behavior': {
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
                                'forward',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'members': {
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
                        'min-bundle': {
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
                        'mode': {
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
                                'static',
                                'lacp-passive',
                                'lacp-active'
                            ],
                            'type': 'str'
                        },
                        'poe-pre-standard-detection': {
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
                        'poe-status': {
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
                        'port-name': {
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
                        'port-owner': {
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
                        'port-security-policy': {
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
                        'port-selection-criteria': {
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
                                'src-mac',
                                'dst-mac',
                                'src-dst-mac',
                                'src-ip',
                                'dst-ip',
                                'src-dst-ip'
                            ],
                            'type': 'str'
                        },
                        'qos-policy': {
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
                        'sample-direction': {
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
                                'rx',
                                'tx',
                                'both'
                            ],
                            'type': 'str'
                        },
                        'sflow-counter-interval': {
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
                        'sflow-sample-rate': {
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
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'type': 'int'
                        },
                        'sflow-sampler': {
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
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'choices': [
                                'disabled',
                                'enabled'
                            ],
                            'type': 'str'
                        },
                        'stp-bpdu-guard': {
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
                                'disabled',
                                'enabled'
                            ],
                            'type': 'str'
                        },
                        'stp-bpdu-guard-timeout': {
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
                        'stp-root-guard': {
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
                                'disabled',
                                'enabled'
                            ],
                            'type': 'str'
                        },
                        'stp-state': {
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
                                'disabled',
                                'enabled'
                            ],
                            'type': 'str'
                        },
                        'type': {
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
                                'physical',
                                'trunk'
                            ],
                            'type': 'str'
                        },
                        'untagged-vlans': {
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
                        'vlan': {
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
                        'export-to-pool-flag': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': False,
                                '6.2.2': True,
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
                            'type': 'int'
                        },
                        'mac-addr': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': False,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
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
                        'packet-sample-rate': {
                            'required': False,
                            'revision': {
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
                        'packet-sampler': {
                            'required': False,
                            'revision': {
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
                                'disabled',
                                'enabled'
                            ],
                            'type': 'str'
                        },
                        'sticky-mac': {
                            'required': False,
                            'revision': {
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
                        'storm-control-policy': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': True,
                                '6.2.2': True,
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
                        'max-miss-heartbeats': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': True,
                                '6.2.2': True,
                                '6.2.6': True,
                                '6.2.7': True,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
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
                            'type': 'int'
                        },
                        'dot1x-enable': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': True,
                                '6.2.2': True,
                                '6.2.6': True,
                                '6.2.7': True,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
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
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'access-mode': {
                            'required': False,
                            'revision': {
                                '6.4.0': True,
                                '6.4.2': True,
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
                                'normal',
                                'nac',
                                'dynamic',
                                'static'
                            ],
                            'type': 'str'
                        },
                        'ip-source-guard': {
                            'required': False,
                            'revision': {
                                '6.4.0': True,
                                '6.4.2': True,
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
                        'mclag-icl-port': {
                            'required': False,
                            'revision': {
                                '6.4.0': True,
                                '6.4.2': True,
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
                        'p2p-port': {
                            'required': False,
                            'revision': {
                                '6.4.0': True,
                                '6.4.2': True,
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
                        'aggregator-mode': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
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
                                'bandwidth',
                                'count'
                            ],
                            'type': 'str'
                        },
                        'rpvst-port': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
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
                                'disabled',
                                'enabled'
                            ],
                            'type': 'str'
                        },
                        'flow-control': {
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
                                'tx',
                                'rx',
                                'both'
                            ],
                            'type': 'str'
                        },
                        'media-type': {
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
                        'pause-meter': {
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
                        'pause-meter-resume': {
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
                                '25%',
                                '50%',
                                '75%'
                            ],
                            'type': 'str'
                        },
                        'trunk-member': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': True,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': False,
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
                        'fec-capable': {
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
                        'fec-state': {
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
                                'disabled',
                                'cl74',
                                'cl91'
                            ],
                            'type': 'str'
                        },
                        'matched-dpp-intf-tags': {
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
                            'type': 'str'
                        },
                        'matched-dpp-policy': {
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
                            'type': 'str'
                        },
                        'port-policy': {
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
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'status': {
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
                                'down',
                                'up'
                            ],
                            'type': 'str'
                        },
                        'dsl-profile': {
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
                            'type': 'str'
                        },
                        'flap-duration': {
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
                                '7.0.2': False,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'int'
                        },
                        'flap-rate': {
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
                                '7.0.2': False,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'int'
                        },
                        'flap-timeout': {
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
                                '7.0.2': False,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'int'
                        },
                        'flapguard': {
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
                                '7.0.2': False,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
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
                        'interface-tags': {
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
                            'type': 'str'
                        },
                        'poe-max-power': {
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
                        'poe-standard': {
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
                        'igmp-snooping-flood-reports': {
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
                        'mcast-snooping-flood-traffic': {
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
                        'link-status': {
                            'required': False,
                            'revision': {
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'down',
                                'up'
                            ],
                            'type': 'str'
                        },
                        'poe-mode-bt-cabable': {
                            'required': False,
                            'revision': {
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'int'
                        },
                        'poe-port-mode': {
                            'required': False,
                            'revision': {
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'ieee802-3af',
                                'ieee802-3at',
                                'ieee802-3bt'
                            ],
                            'type': 'str'
                        },
                        'poe-port-power': {
                            'required': False,
                            'revision': {
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'normal',
                                'perpetual',
                                'perpetual-fast'
                            ],
                            'type': 'str'
                        },
                        'poe-port-priority': {
                            'required': False,
                            'revision': {
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'critical-priority',
                                'high-priority',
                                'low-priority',
                                'medium-priority'
                            ],
                            'type': 'str'
                        },
                        'acl-group': {
                            'required': False,
                            'revision': {
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'dhcp-snoop-option82-override': {
                            'required': False,
                            'revision': {
                                '7.4.0': True
                            },
                            'type': 'list',
                            'options': {
                                'circuit-id': {
                                    'required': False,
                                    'revision': {
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'remote-id': {
                                    'required': False,
                                    'revision': {
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                },
                                'vlan-name': {
                                    'required': False,
                                    'revision': {
                                        '7.4.0': True
                                    },
                                    'type': 'str'
                                }
                            },
                            'elements': 'dict'
                        },
                        'fortiswitch-acls': {
                            'required': False,
                            'revision': {
                                '7.4.0': True
                            },
                            'type': 'int'
                        },
                        'isl-peer-device-sn': {
                            'required': False,
                            'revision': {
                                '7.4.0': True
                            },
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'switch-id': {
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
                'override-snmp-community': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': False,
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
                'override-snmp-sysinfo': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': False,
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
                'override-snmp-trap-threshold': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': False,
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
                'override-snmp-user': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': False,
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
                'poe-detection-type': {
                    'required': False,
                    'revision': {
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
                'remote-log': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': False,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False,
                        '6.2.0': False,
                        '6.2.2': True,
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
                    'type': 'list',
                    'options': {
                        'csv': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': False,
                                '6.2.2': True,
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
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'facility': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': False,
                                '6.2.2': True,
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
                                'kernel',
                                'user',
                                'mail',
                                'daemon',
                                'auth',
                                'syslog',
                                'lpr',
                                'news',
                                'uucp',
                                'cron',
                                'authpriv',
                                'ftp',
                                'ntp',
                                'audit',
                                'alert',
                                'clock',
                                'local0',
                                'local1',
                                'local2',
                                'local3',
                                'local4',
                                'local5',
                                'local6',
                                'local7'
                            ],
                            'type': 'str'
                        },
                        'name': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': False,
                                '6.2.2': True,
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
                        'port': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': False,
                                '6.2.2': True,
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
                            'type': 'int'
                        },
                        'server': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': False,
                                '6.2.2': True,
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
                        'severity': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': False,
                                '6.2.2': True,
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
                                'emergency',
                                'alert',
                                'critical',
                                'error',
                                'warning',
                                'notification',
                                'information',
                                'debug'
                            ],
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': False,
                                '6.2.2': True,
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
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'snmp-community': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': False,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False,
                        '6.2.0': False,
                        '6.2.2': True,
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
                    'type': 'list',
                    'options': {
                        'events': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': False,
                                '6.2.2': True,
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
                            'type': 'list',
                            'choices': [
                                'cpu-high',
                                'mem-low',
                                'log-full',
                                'intf-ip',
                                'ent-conf-change'
                            ],
                            'elements': 'str'
                        },
                        'hosts': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': False,
                                '6.2.2': True,
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
                            'type': 'list',
                            'options': {
                                'id': {
                                    'required': False,
                                    'revision': {
                                        '6.2.1': True,
                                        '6.2.3': True,
                                        '6.2.5': False,
                                        '6.4.0': False,
                                        '6.4.2': False,
                                        '6.4.5': False,
                                        '7.0.0': False,
                                        '7.2.0': False,
                                        '6.2.0': False,
                                        '6.2.2': True,
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
                                    'type': 'int'
                                },
                                'ip': {
                                    'required': False,
                                    'revision': {
                                        '6.2.1': True,
                                        '6.2.3': True,
                                        '6.2.5': False,
                                        '6.4.0': False,
                                        '6.4.2': False,
                                        '6.4.5': False,
                                        '7.0.0': False,
                                        '7.2.0': False,
                                        '6.2.0': False,
                                        '6.2.2': True,
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
                                }
                            },
                            'elements': 'dict'
                        },
                        'id': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': False,
                                '6.2.2': True,
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
                            'type': 'int'
                        },
                        'name': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': False,
                                '6.2.2': True,
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
                        'query-v1-port': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': False,
                                '6.2.2': True,
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
                            'type': 'int'
                        },
                        'query-v1-status': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': False,
                                '6.2.2': True,
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
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'query-v2c-port': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': False,
                                '6.2.2': True,
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
                            'type': 'int'
                        },
                        'query-v2c-status': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': False,
                                '6.2.2': True,
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
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': False,
                                '6.2.2': True,
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
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'trap-v1-lport': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': False,
                                '6.2.2': True,
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
                            'type': 'int'
                        },
                        'trap-v1-rport': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': False,
                                '6.2.2': True,
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
                            'type': 'int'
                        },
                        'trap-v1-status': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': False,
                                '6.2.2': True,
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
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'trap-v2c-lport': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': False,
                                '6.2.2': True,
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
                            'type': 'int'
                        },
                        'trap-v2c-rport': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': False,
                                '6.2.2': True,
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
                            'type': 'int'
                        },
                        'trap-v2c-status': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': False,
                                '6.2.2': True,
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
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'snmp-user': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': False,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False,
                        '6.2.0': False,
                        '6.2.2': True,
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
                    'type': 'list',
                    'options': {
                        'auth-proto': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': False,
                                '6.2.2': True,
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
                                'md5',
                                'sha'
                            ],
                            'type': 'str'
                        },
                        'auth-pwd': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': False,
                                '6.2.2': True,
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
                        'name': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': False,
                                '6.2.2': True,
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
                        'priv-proto': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': False,
                                '6.2.2': True,
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
                                'des',
                                'aes'
                            ],
                            'type': 'str'
                        },
                        'priv-pwd': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': False,
                                '6.2.2': True,
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
                        'queries': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': False,
                                '6.2.2': True,
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
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'query-port': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': False,
                                '6.2.2': True,
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
                            'type': 'int'
                        },
                        'security-level': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': False,
                                '6.2.2': True,
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
                                'no-auth-no-priv',
                                'auth-no-priv',
                                'auth-priv'
                            ],
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'mclag-igmp-snooping-aware': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': False,
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
                'ip-source-guard': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False,
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.4.1': True,
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
                    'type': 'list',
                    'options': {
                        'binding-entry': {
                            'required': False,
                            'revision': {
                                '6.4.0': True,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': True,
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
                            'type': 'list',
                            'options': {
                                'entry-name': {
                                    'required': False,
                                    'revision': {
                                        '6.4.0': True,
                                        '6.4.2': False,
                                        '6.4.5': False,
                                        '7.0.0': False,
                                        '7.2.0': False,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': False,
                                        '6.2.9': False,
                                        '6.2.10': False,
                                        '6.4.1': True,
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
                                'ip': {
                                    'required': False,
                                    'revision': {
                                        '6.4.0': True,
                                        '6.4.2': False,
                                        '6.4.5': False,
                                        '7.0.0': False,
                                        '7.2.0': False,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': False,
                                        '6.2.9': False,
                                        '6.2.10': False,
                                        '6.4.1': True,
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
                                'mac': {
                                    'required': False,
                                    'revision': {
                                        '6.4.0': True,
                                        '6.4.2': False,
                                        '6.4.5': False,
                                        '7.0.0': False,
                                        '7.2.0': False,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': False,
                                        '6.2.9': False,
                                        '6.2.10': False,
                                        '6.4.1': True,
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
                                }
                            },
                            'elements': 'dict'
                        },
                        'description': {
                            'required': False,
                            'revision': {
                                '6.4.0': True,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': True,
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
                        'port': {
                            'required': False,
                            'revision': {
                                '6.4.0': True,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False,
                                '7.2.0': False,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': False,
                                '6.2.9': False,
                                '6.2.10': False,
                                '6.4.1': True,
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
                        }
                    },
                    'elements': 'dict'
                },
                'l3-discovered': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': True,
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
                'qos-drop-policy': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': True,
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
                        'taildrop',
                        'random-early-detection'
                    ],
                    'type': 'str'
                },
                'qos-red-probability': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': True,
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
                'switch-dhcp_opt43_key': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': True,
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
                'tdr-supported': {
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
                'custom-command': {
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
                    'type': 'list',
                    'options': {
                        'command-entry': {
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
                            'type': 'str'
                        },
                        'command-name': {
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
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'firmware-provision': {
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
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'firmware-provision-version': {
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
                    'type': 'str'
                },
                'dhcp-server-access-list': {
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
                        'enable',
                        'global'
                    ],
                    'type': 'str'
                },
                'firmware-provision-latest': {
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
                        '7.0.2': False,
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
                        'once'
                    ],
                    'type': 'str'
                },
                'dhcp-snooping-static-client': {
                    'required': False,
                    'revision': {
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'list',
                    'options': {
                        'ip': {
                            'required': False,
                            'revision': {
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'mac': {
                            'required': False,
                            'revision': {
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'name': {
                            'required': False,
                            'revision': {
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'port': {
                            'required': False,
                            'revision': {
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'vlan': {
                            'required': False,
                            'revision': {
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_managedswitch'),
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

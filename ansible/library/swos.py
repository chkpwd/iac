#!/usr/bin/python
# -*- coding: utf-8 -*-


from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: swos
short_description: Manage MikroTik SwOS and SwOS Lite switch configuration
version_added: "1.0.0"
description:
    - Manages configuration of MikroTik switches running SwOS or SwOS Lite
    - Automatically detects platform type (SwOS vs SwOS Lite) and adapts accordingly
    - Supports SwOS Lite 2.20+ (CSS series) and SwOS 2.14+ (CRS/RB series)
    - Supports configuring ports, PoE, LAG/LACP, VLANs, and SNMP
    - Implements idempotent operations (only applies changes when needed)
    - Supports check mode for dry-run validation
    - Only modifies writable settings (read-only settings like link status are ignored)
options:
    host:
        description:
            - IP address or hostname of the switch
            - Can be provided with or without http:// prefix
        required: true
        type: str
    username:
        description:
            - Username for authentication
            - Uses HTTP Digest Authentication
        required: false
        default: admin
        type: str
    password:
        description:
            - Password for authentication
            - Use Ansible Vault for secure password storage
        required: false
        default: ""
        type: str
    config:
        description:
            - Complete switch configuration dictionary organized by sections
            - Supported sections are system, ports, poe, lag, port_vlans, vlans, snmp
            - Most sections contain lists of per-port configurations
            - Only specified settings in each section will be evaluated for changes
        required: false
        type: dict
        suboptions:
            system:
                description:
                    - System configuration dictionary
                type: dict
                suboptions:
                    identity:
                        description: Device identity/name
                        type: str
                    address_acquisition:
                        description: IP address acquisition mode
                        type: str
                        choices: ['DHCP with fallback', 'static', 'DHCP only']
                    static_ip:
                        description: Static/fallback IP address
                        type: str
                    allow_from:
                        description: IP/CIDR restriction for management access (empty string removes restriction)
                        type: str
                    allow_from_ports:
                        description: List of port numbers allowed for management access
                        type: list
                        elements: int
                    allow_from_vlan:
                        description: VLAN ID allowed for management access
                        type: int
            ports:
                description:
                    - List of port configuration dictionaries
                type: list
                elements: dict
                suboptions:
                    port:
                        description: Port number (1-based)
                        required: true
                        type: int
                    name:
                        description: Port name
                        type: str
                    enabled:
                        description: Port enabled state
                        type: bool
                    auto_negotiation:
                        description: Auto-negotiation enabled
                        type: bool
            poe:
                description:
                    - List of PoE configuration dictionaries
                type: list
                elements: dict
                suboptions:
                    port:
                        description: Port number (1-based)
                        required: true
                        type: int
                    mode:
                        description: PoE mode
                        type: str
                        choices: ['off', 'on', 'auto']
                    priority:
                        description: PoE priority (1-8, where 1 is highest)
                        type: int
                    voltage_level:
                        description: Voltage level setting
                        type: str
                        choices: ['auto', 'low', 'high']
                    lldp_enabled:
                        description: LLDP enabled state
                        type: bool
            lag:
                description:
                    - List of LAG/LACP configuration dictionaries
                type: list
                elements: dict
                suboptions:
                    port:
                        description: Port number (1-based)
                        required: true
                        type: int
                    mode:
                        description: LACP mode
                        type: str
                        choices: ['passive', 'active', 'static']
                    group:
                        description: LAG group number
                        type: int
            port_vlans:
                description:
                    - List of per-port VLAN configuration dictionaries
                type: list
                elements: dict
                suboptions:
                    port:
                        description: Port number (1-based)
                        required: true
                        type: int
                    vlan_mode:
                        description: >
                            VLAN mode. SwOS supports all 4 modes.
                            SwOS Lite only supports Disabled, Optional, Strict (not Enabled).
                        type: str
                        choices: ['Disabled', 'Optional', 'Enabled', 'Strict']
                    vlan_receive:
                        description: VLAN receive filter
                        type: str
                        choices: ['Any', 'Only Tagged', 'Only Untagged']
                    default_vlan_id:
                        description: Default VLAN ID for untagged traffic
                        type: int
                    force_vlan_id:
                        description: Force VLAN ID on this port
                        type: bool
            vlans:
                description:
                    - List of VLAN table entries
                    - Defines which ports are members of each VLAN
                type: list
                elements: dict
                suboptions:
                    vlan_id:
                        description: VLAN ID (1-4094)
                        required: true
                        type: int
                    member_ports:
                        description: List of port numbers that are members of this VLAN
                        required: true
                        type: list
                        elements: int
                    igmp_snooping:
                        description: Enable IGMP snooping for this VLAN
                        type: bool
                        default: false
                    name:
                        description: VLAN name (SwOS only, ignored on SwOS Lite)
                        type: str
                    isolation:
                        description: Enable port isolation for this VLAN (SwOS only, ignored on SwOS Lite)
                        type: bool
                    learning:
                        description: Enable MAC learning for this VLAN (SwOS only, ignored on SwOS Lite)
                        type: bool
                    mirror:
                        description: Enable traffic mirroring for this VLAN (SwOS only, ignored on SwOS Lite)
                        type: bool
            snmp:
                description:
                    - SNMP configuration dictionary
                type: dict
                suboptions:
                    enabled:
                        description: SNMP enabled state
                        type: bool
                    community:
                        description: SNMP community string
                        type: str
                    contact:
                        description: Contact information
                        type: str
                    location:
                        description: Device location
                        type: str
            vlan_groups:
                description:
                    - Dictionary of named VLAN groups for reuse across ports
                    - Keys are group names, values are lists of VLAN IDs
                    - Used with port_config to reduce redundancy
                type: dict
            port_config:
                description:
                    - Simplified per-port VLAN configuration using access/trunk model
                    - Alternative to the detailed port_vlans format
                    - Automatically generates port_vlans and vlans sections
                    - Can be used alongside vlans section for additional settings (igmp_snooping, etc.)
                type: dict
                suboptions:
                    mode:
                        description: Port mode
                        type: str
                        choices: ['access', 'trunk']
                        required: true
                    vlan:
                        description: VLAN ID for access ports (required for access mode)
                        type: int
                    native_vlan:
                        description: Native VLAN ID for trunk ports (default 1)
                        type: int
                        default: 1
                    allowed_vlans:
                        description: List of allowed VLAN IDs for trunk ports
                        type: list
                        elements: int
                    vlan_group:
                        description: >
                            Reference to a vlan_groups entry (alternative to allowed_vlans).
                            If neither allowed_vlans nor vlan_group is specified for a trunk port,
                            defaults to all VLANs referenced in the configuration.
                        type: str
                    vlan_mode:
                        description: >
                            Override the default vlan_mode. By default, trunk ports use 'Optional'
                            and access ports use 'Strict'. Use this to specify 'Enabled' for SwOS
                            switches that need stricter 802.1Q enforcement. Note that 'Enabled' is
                            not supported on SwOS Lite (CSS series).
                        type: str
                        choices: ['Disabled', 'Optional', 'Enabled', 'Strict']
    port_vlans:
        description:
            - List of port VLAN configurations (deprecated, use config.port_vlans)
        required: false
        type: list
        elements: dict
notes:
    - Requires swos Python package (pip install mikrotik-swos)
    - Automatically detects SwOS vs SwOS Lite and uses appropriate field mappings
    - Supports both CSS series (SwOS Lite) and CRS/RB series (SwOS) switches
    - Only applies changes when configuration differs from current state
    - All write operations send complete configuration to the switch
    - Read-only settings are automatically ignored
    - Use check mode (--check) to preview changes without applying them
requirements:
    - requests>=2.25.0
author:
    - SwOS Ansible Module Contributors
'''

EXAMPLES = r'''
# Apply complete configuration from YAML file
- name: Apply switch configuration
  swos:
    host: 192.168.88.1
    username: admin
    password: ""
    config: "{{ lookup('file', 'switch_config.yml') | from_yaml }}"
  register: result

# Configure port settings only
- name: Configure port names and states
  swos:
    host: 192.168.88.1
    config:
      ports:
        - port: 1
          name: "Uplink"
          enabled: true
          auto_negotiation: true
        - port: 2
          name: "Server1"
          enabled: true

# Configure PoE settings
- name: Configure PoE on multiple ports
  swos:
    host: 192.168.88.1
    config:
      poe:
        - port: 1
          mode: "auto"
          priority: 1
          voltage_level: "auto"
          lldp_enabled: true
        - port: 2
          mode: "off"

# Configure LAG/LACP
- name: Configure LACP trunk
  swos:
    host: 192.168.88.1
    config:
      lag:
        - port: 9
          mode: "active"
          group: 1
        - port: 10
          mode: "active"
          group: 1

# Configure per-port VLANs (detailed format)
- name: Configure port VLANs
  swos:
    host: 192.168.88.1
    config:
      port_vlans:
        - port: 3
          vlan_mode: "Enabled"
          vlan_receive: "Only Untagged"
          default_vlan_id: 64
        - port: 4
          vlan_mode: "Optional"
          vlan_receive: "Any"
          default_vlan_id: 1

# Simplified port configuration using access/trunk model
# This automatically generates port_vlans and vlans sections
- name: Configure ports with simplified access/trunk format
  swos:
    host: 192.168.88.1
    config:
      vlan_groups:
        all_vlans: [1, 64, 539]
        servers: [1, 64]
      port_config:
        1:
          mode: trunk
          native_vlan: 1
          vlan_group: all_vlans      # Reference a VLAN group
        2:
          mode: trunk
          native_vlan: 1
          allowed_vlans: [1, 64]     # Or specify VLANs directly
        3:
          mode: access
          vlan: 64
        9:
          mode: trunk                # No allowed_vlans = all referenced VLANs
          native_vlan: 1

# Simplified format with additional VLAN settings
- name: Configure ports with IGMP snooping
  swos:
    host: 192.168.88.1
    config:
      port_config:
        1:
          mode: trunk
          native_vlan: 1
          allowed_vlans: [1, 64]
        3:
          mode: access
          vlan: 64
      vlans:
        # These settings are merged with auto-generated VLAN entries
        - vlan_id: 64
          igmp_snooping: true

# Configure VLAN table
- name: Configure VLAN table with SwOS-only features
  swos:
    host: 192.168.88.1
    config:
      vlans:
        - vlan_id: 1
          member_ports: [1, 2, 3, 4, 5, 6, 7, 8]
        - vlan_id: 10
          member_ports: [1, 2, 3]
          igmp_snooping: true
          name: "Management"        # SwOS only
        - vlan_id: 20
          member_ports: [4, 5, 6]
          name: "Servers"           # SwOS only
          isolation: true           # SwOS only
          learning: true            # SwOS only

# Configure SNMP
- name: Configure SNMP settings
  swos:
    host: 192.168.88.1
    config:
      snmp:
        enabled: true
        community: "public"
        contact: "admin@example.com"
        location: "Server Room A"

# Configure multiple sections at once
- name: Configure ports, PoE, and VLANs
  swos:
    host: 192.168.88.1
    username: admin
    password: ""
    config:
      ports:
        - port: 1
          name: "Uplink"
          enabled: true
      poe:
        - port: 2
          mode: "auto"
          priority: 1
      port_vlans:
        - port: 3
          vlan_mode: "Enabled"
          default_vlan_id: 100

# Use with Ansible Vault for password
- name: Apply configuration with vault password
  swos:
    host: 192.168.88.1
    username: admin
    password: "{{ vault_switch_password }}"
    config: "{{ switch_config }}"

# Check mode - preview changes without applying
- name: Preview configuration changes
  swos:
    host: 192.168.88.1
    config: "{{ switch_config }}"
  check_mode: yes
'''

RETURN = r'''
changed:
    description: Whether any changes were made to the switch configuration
    type: bool
    returned: always
    sample: true
msg:
    description: Human-readable message describing what was changed
    type: str
    returned: always
    sample: "Changed 3 setting(s): Port 1 config (name 'Port1'->'Uplink'); Port 2 PoE (mode auto->off); Port 3 VLAN (mode Optional->Enabled)"
current_config:
    description: Current configuration after changes (only if changes were made)
    type: dict
    returned: success
    contains:
        ports:
            description: Current port configuration (if ports section was provided)
            type: list
            returned: when ports were configured
        poe:
            description: Current PoE configuration (if poe section was provided)
            type: list
            returned: when PoE was configured
        lag:
            description: Current LAG configuration (if lag section was provided)
            type: list
            returned: when LAG was configured
        port_vlans:
            description: Current per-port VLAN configuration (if port_vlans section was provided)
            type: list
            returned: when VLANs were configured
    sample:
        port_vlans:
            - port_number: 1
              vlan_mode: "Optional"
              vlan_receive: "Any"
              default_vlan_id: 1
'''

from ansible.module_utils.basic import AnsibleModule
import sys
import os

try:
    from swos import (
        get_port_vlans, set_port_vlan,
        get_vlans, set_vlans,
        get_links, set_port_config,
        get_poe, set_poe_config,
        get_lag, set_lag_config,
        get_snmp, set_snmp,
        get_system_info, set_system,
        get_backup
    )
    from swos.platform import detect_platform, PlatformType
    HAS_SWOS_API = True
except ImportError:
    HAS_SWOS_API = False


def normalize_yaml_boolean(value, on_value='on', off_value='off'):
    """
    Normalize YAML boolean values to strings.

    In YAML, 'off', 'no', 'false' are parsed as boolean False,
    and 'on', 'yes', 'true' are parsed as boolean True.
    This function converts them back to the expected string values.

    Args:
        value: The value to normalize
        on_value: String to return for True (default: 'on')
        off_value: String to return for False (default: 'off')

    Returns:
        Normalized string value, or original value if not a boolean
    """
    if value is True:
        return on_value
    elif value is False:
        return off_value
    return value


def normalize_poe_config(poe_cfg):
    """
    Normalize PoE configuration values that may have been parsed as YAML booleans.

    Specifically handles 'mode: off' being parsed as mode: False.
    """
    if 'mode' in poe_cfg:
        poe_cfg['mode'] = normalize_yaml_boolean(poe_cfg['mode'], on_value='on', off_value='off')
    return poe_cfg


def port_vlan_matches(current, desired):
    """Check if current port VLAN config matches desired config"""
    matches = True

    if 'vlan_mode' in desired and current.get('vlan_mode') != desired['vlan_mode']:
        matches = False

    if 'vlan_receive' in desired and current.get('vlan_receive') != desired['vlan_receive']:
        matches = False

    if 'default_vlan_id' in desired and current.get('default_vlan_id') != desired['default_vlan_id']:
        matches = False

    if 'force_vlan_id' in desired and current.get('force_vlan_id') != desired['force_vlan_id']:
        matches = False

    return matches


def port_config_matches(current, desired):
    """Check if current port config matches desired config"""
    matches = True

    if 'name' in desired and current.get('port_name') != desired['name']:
        matches = False

    if 'enabled' in desired and current.get('enabled') != desired['enabled']:
        matches = False

    if 'auto_negotiation' in desired and current.get('auto_negotiation') != desired['auto_negotiation']:
        matches = False

    return matches


def poe_config_matches(current, desired):
    """Check if current PoE config matches desired config"""
    matches = True

    if 'mode' in desired and current.get('poe_mode') != desired['mode']:
        matches = False

    if 'priority' in desired and current.get('poe_priority') != desired['priority']:
        matches = False

    if 'voltage_level' in desired and current.get('voltage_level') != desired['voltage_level']:
        matches = False

    if 'lldp_enabled' in desired and current.get('lldp_enabled') != desired['lldp_enabled']:
        matches = False

    return matches


def lag_config_matches(current, desired):
    """Check if current LAG config matches desired config"""
    matches = True

    if 'mode' in desired and current.get('lacp_mode') != desired['mode']:
        matches = False

    if 'group' in desired and current.get('lacp_group') != desired['group']:
        matches = False

    return matches


def snmp_config_matches(current, desired):
    """Check if current SNMP config matches desired config"""
    matches = True

    if 'enabled' in desired and current.get('enabled') != desired['enabled']:
        matches = False

    if 'community' in desired and current.get('community') != desired['community']:
        matches = False

    if 'contact' in desired and current.get('contact') != desired['contact']:
        matches = False

    if 'location' in desired and current.get('location') != desired['location']:
        matches = False

    return matches


def system_config_matches(current, desired):
    """Check if current system config matches desired config"""
    matches = True

    if 'identity' in desired and current.get('identity') != desired['identity']:
        matches = False

    if 'address_acquisition' in desired and current.get('address_acquisition') != desired['address_acquisition']:
        matches = False

    if 'static_ip' in desired and current.get('static_ip') != desired['static_ip']:
        matches = False

    if 'allow_from' in desired and current.get('allow_from') != desired['allow_from']:
        matches = False

    if 'allow_from_ports' in desired:
        if sorted(current.get('allow_from_ports', [])) != sorted(desired['allow_from_ports']):
            matches = False

    if 'allow_from_vlan' in desired and current.get('allow_from_vlan') != desired['allow_from_vlan']:
        matches = False

    return matches


def is_swos_lite(platform_type):
    """Check if platform is SwOS Lite (CSS series)."""
    return platform_type == PlatformType.SWOS_LITE


def vlans_match(current_vlans, desired_vlans, platform_type=None):
    """Check if current VLAN table matches desired VLAN table

    Compares two lists of VLANs by vlan_id, member_ports, igmp_snooping,
    and SwOS-only fields (name, isolation, learning, mirror).
    Returns True if they match exactly (same VLANs with same settings).

    Args:
        current_vlans: List of VLAN dicts from the switch
        desired_vlans: List of desired VLAN dicts from config
        platform_type: Platform type (PlatformType.SWOS or PlatformType.SWOS_LITE)
                      If None, SwOS-only fields are always compared.
    """
    # Create dictionaries keyed by vlan_id for easier comparison
    current_dict = {v['vlan_id']: v for v in current_vlans}
    desired_dict = {v['vlan_id']: v for v in desired_vlans}

    # Check if VLAN IDs match
    if set(current_dict.keys()) != set(desired_dict.keys()):
        return False

    # Check each VLAN's settings
    for vlan_id in desired_dict:
        current = current_dict[vlan_id]
        desired = desired_dict[vlan_id]

        # Compare member ports (as sorted lists for comparison)
        if sorted(current['member_ports']) != sorted(desired['member_ports']):
            return False

        # Compare IGMP snooping (default to False if not specified)
        current_igmp = current.get('igmp_snooping', False)
        desired_igmp = desired.get('igmp_snooping', False)
        if current_igmp != desired_igmp:
            return False

        # Compare SwOS-only fields (only if specified in desired config AND platform supports them)
        # Skip these comparisons on SwOS Lite since it doesn't support these fields
        if platform_type is None or not is_swos_lite(platform_type):
            if 'name' in desired:
                current_name = current.get('name') or ''
                desired_name = desired.get('name') or ''
                if current_name != desired_name:
                    return False

            if 'isolation' in desired:
                current_isolation = current.get('isolation') if current.get('isolation') is not None else False
                if current_isolation != desired['isolation']:
                    return False

            if 'learning' in desired:
                current_learning = current.get('learning') if current.get('learning') is not None else True
                if current_learning != desired['learning']:
                    return False

            if 'mirror' in desired:
                current_mirror = current.get('mirror') if current.get('mirror') is not None else False
                if current_mirror != desired['mirror']:
                    return False

    return True


# ============================================================================
# Simplified port_config Format Preprocessing
# ============================================================================

def uses_simplified_format(config):
    """Detect if config uses simplified port_config format."""
    return config and 'port_config' in config


def validate_port_config_entry(port_cfg, port_num):
    """Validate a single port configuration entry."""
    mode = port_cfg.get('mode')
    if mode not in ('access', 'trunk'):
        raise ValueError(f"Port {port_num}: mode must be 'access' or 'trunk', got '{mode}'")
    if mode == 'access' and 'vlan' not in port_cfg:
        raise ValueError(f"Port {port_num}: access mode requires 'vlan' field")

    # Validate vlan_mode override if provided
    vlan_mode = port_cfg.get('vlan_mode')
    if vlan_mode is not None:
        valid_modes = ('Disabled', 'Optional', 'Enabled', 'Strict')
        if vlan_mode not in valid_modes:
            raise ValueError(f"Port {port_num}: vlan_mode must be one of {valid_modes}, got '{vlan_mode}'")


def collect_all_vlans(port_config, vlan_groups, existing_vlans):
    """Collect all VLANs referenced anywhere in the configuration."""
    all_vlans = set()

    for port_cfg in port_config.values():
        if 'vlan' in port_cfg:
            all_vlans.add(port_cfg['vlan'])
        if 'native_vlan' in port_cfg:
            all_vlans.add(port_cfg['native_vlan'])
        if 'allowed_vlans' in port_cfg:
            all_vlans.update(port_cfg['allowed_vlans'])

    for group_vlans in vlan_groups.values():
        all_vlans.update(group_vlans)

    for vlan in existing_vlans:
        all_vlans.add(vlan['vlan_id'])

    return all_vlans


def get_allowed_vlans_for_port(port_cfg, port_num, vlan_groups, all_vlans, warnings):
    """Get the set of allowed VLANs for a port.

    Args:
        port_cfg: Port configuration dict
        port_num: Port number (for warning messages)
        vlan_groups: Dictionary of VLAN group definitions
        all_vlans: Set of all VLANs referenced in config
        warnings: List to append warning messages to

    Returns:
        Set of allowed VLAN IDs for this port
    """
    mode = port_cfg.get('mode', 'access')

    if mode == 'access':
        return {port_cfg['vlan']}

    # Trunk mode
    if 'allowed_vlans' in port_cfg:
        vlans = set(port_cfg['allowed_vlans'])
    elif 'vlan_group' in port_cfg:
        group = port_cfg['vlan_group']
        if group not in vlan_groups:
            raise ValueError(f"Unknown vlan_group: '{group}'")
        vlans = set(vlan_groups[group])
    else:
        # Default: all VLANs referenced anywhere in config
        vlans = set(all_vlans)

    # Always include native VLAN for trunk ports (required for 802.1Q)
    native = port_cfg.get('native_vlan', 1)
    if native not in vlans:
        warnings.append(
            f"Port {port_num}: native_vlan {native} not in allowed VLANs, "
            f"automatically added (native VLAN is always allowed on trunk ports)"
        )
        vlans.add(native)
    return vlans


def transform_port_to_detailed(port_num, port_cfg):
    """Transform a single port config to detailed port_vlans format.

    Supports optional vlan_mode override for cases where the default
    mode (Optional for trunk, Strict for access) isn't appropriate.
    """
    mode = port_cfg.get('mode', 'access')

    # Check for vlan_mode override
    vlan_mode_override = port_cfg.get('vlan_mode')

    if mode == 'access':
        return {
            'port': port_num,
            'vlan_mode': vlan_mode_override or 'Strict',
            'vlan_receive': 'Only Untagged',
            'default_vlan_id': port_cfg['vlan'],
            'force_vlan_id': True
        }
    elif mode == 'trunk':
        return {
            'port': port_num,
            'vlan_mode': vlan_mode_override or 'Optional',
            'vlan_receive': 'Any',
            'default_vlan_id': port_cfg.get('native_vlan', 1),
            'force_vlan_id': False
        }


def generate_vlans_table(vlan_membership):
    """Generate vlans section from port membership tracking."""
    return [
        {'vlan_id': vid, 'member_ports': sorted(ports)}
        for vid, ports in sorted(vlan_membership.items())
    ]


def merge_vlans_tables(existing, generated):
    """Merge existing vlans (with extra settings like igmp_snooping) with generated."""
    existing_dict = {v['vlan_id']: v for v in existing}
    generated_dict = {v['vlan_id']: v for v in generated}

    merged = []
    for vid in sorted(set(existing_dict.keys()) | set(generated_dict.keys())):
        if vid in existing_dict and vid in generated_dict:
            # Merge: use existing as base, update member_ports
            entry = dict(existing_dict[vid])
            existing_ports = set(entry.get('member_ports', []))
            generated_ports = set(generated_dict[vid]['member_ports'])
            entry['member_ports'] = sorted(existing_ports | generated_ports)
            merged.append(entry)
        elif vid in existing_dict:
            # VLAN only in existing config - ensure member_ports exists
            entry = dict(existing_dict[vid])
            if 'member_ports' not in entry:
                entry['member_ports'] = []
            merged.append(entry)
        else:
            merged.append(generated_dict[vid])

    return merged


def preprocess_port_config(config):
    """
    Transform simplified port_config format to detailed port_vlans/vlans format.

    If the config already uses the detailed format (no port_config key),
    returns the config unchanged along with an empty warnings list.

    Simplified format example:
        vlan_groups:
          all_vlans: [1, 64, 539]
        port_config:
          1:
            mode: trunk
            native_vlan: 1
            vlan_group: all_vlans
          3:
            mode: access
            vlan: 64

    Transforms to:
        port_vlans:
          - port: 1
            vlan_mode: Optional
            vlan_receive: Any
            default_vlan_id: 1
            force_vlan_id: false
          - port: 3
            vlan_mode: Strict
            vlan_receive: Only Untagged
            default_vlan_id: 64
            force_vlan_id: true
        vlans:
          - vlan_id: 1
            member_ports: [1]
          - vlan_id: 64
            member_ports: [1, 3]
          - vlan_id: 539
            member_ports: [1]

    Returns:
        Tuple of (config, warnings) where warnings is a list of warning messages
    """
    if not uses_simplified_format(config):
        return config, []

    # Make a copy to avoid modifying the original
    config = dict(config)
    warnings = []

    # Extract simplified format sections
    vlan_groups = config.pop('vlan_groups', {})
    port_config = config.pop('port_config', {})
    existing_vlans = config.get('vlans', [])

    # Collect all VLANs referenced anywhere
    all_vlans = collect_all_vlans(port_config, vlan_groups, existing_vlans)

    # Transform each port and track VLAN membership
    port_vlans_list = []
    vlan_membership = {}  # {vlan_id: set(port_numbers)}

    for port_key, port_cfg in port_config.items():
        port_num = int(port_key)

        # Validate the port configuration
        validate_port_config_entry(port_cfg, port_num)

        # Get allowed VLANs for this port
        allowed = get_allowed_vlans_for_port(port_cfg, port_num, vlan_groups, all_vlans, warnings)

        # Transform to detailed format
        detailed = transform_port_to_detailed(port_num, port_cfg)
        port_vlans_list.append(detailed)

        # Track VLAN membership for vlans table generation
        for vlan_id in allowed:
            vlan_membership.setdefault(vlan_id, set()).add(port_num)

    # Generate vlans table from port memberships and merge with existing
    generated_vlans = generate_vlans_table(vlan_membership)
    config['vlans'] = merge_vlans_tables(existing_vlans, generated_vlans)
    config['port_vlans'] = port_vlans_list

    return config, warnings


def run_module():
    module_args = dict(
        host=dict(type='str', required=True),
        username=dict(type='str', required=False, default='admin'),
        password=dict(type='str', required=False, default='', no_log=True),
        # LOCAL PATCH: override platform detection, which maps every "CSS*"
        # board to SwOS Lite even though the CSS318 speaks full SwOS.
        platform=dict(type='str', required=False, default=None,
                      choices=['swos', 'swos-lite']),
        config=dict(type='dict', required=False, default={}),
        port_vlans=dict(type='list', elements='dict', required=False, default=[]),
        backup=dict(type='bool', required=False, default=False),
        backup_options=dict(
            type='dict',
            required=False,
            options=dict(
                filename=dict(type='str', required=False),
                dir_path=dict(type='path', required=False, default='./backups')
            )
        ),
    )

    result = dict(
        changed=False,
        msg='',
        current_config={}
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    if not HAS_SWOS_API:
        module.fail_json(msg='swos module is required. Install with: pip install mikrotik-swos')

    host = module.params['host']
    username = module.params['username']
    password = module.params['password']
    platform_override = module.params['platform']
    config = module.params['config']
    port_vlans = module.params['port_vlans']
    backup = module.params['backup']
    backup_options = module.params['backup_options'] or {}

    # patch swos.platform.detect_platform so both this module and
    # the library's internal PlatformAdapter honour the forced platform.
    if platform_override:
        import swos.platform as _swp
        _forced = {'swos': PlatformType.SWOS,
                   'swos-lite': PlatformType.SWOS_LITE}[platform_override]
        _swp.detect_platform = lambda *a, **k: _forced
        global detect_platform
        detect_platform = _swp.detect_platform

    # Preprocess simplified port_config format to detailed format
    if config:
        try:
            config, preprocess_warnings = preprocess_port_config(config)
            for warning in preprocess_warnings:
                module.warn(warning)
        except ValueError as e:
            module.fail_json(msg=str(e))

    # Support both new config format and old port_vlans parameter
    if config and 'port_vlans' in config:
        port_vlans = config['port_vlans']

    # Build URL
    if not host.startswith('http'):
        url = f"http://{host}"
    else:
        url = host

    # Detect platform type (SwOS vs SwOS Lite)
    try:
        platform_type = detect_platform(url, username, password)
    except Exception as e:
        module.fail_json(msg=f"Failed to detect switch platform: {e}")

    try:
        # Create backup before making any changes
        if backup and not module.check_mode:
            try:
                # Get backup data from switch
                backup_data = get_backup(url, username, password)

                # Prepare backup directory and filename
                backup_dir = backup_options.get('dir_path', './backups')

                # Create backup directory if it doesn't exist
                if not os.path.exists(backup_dir):
                    os.makedirs(backup_dir, mode=0o755)

                # Generate filename if not provided
                if backup_options.get('filename'):
                    backup_filename = backup_options['filename']
                else:
                    # Use host_timestamp.swb format
                    from datetime import datetime
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    # Extract hostname for filename (remove http:// prefix if present)
                    hostname = host.replace('http://', '').replace('https://', '').replace(':', '_').replace('/', '_')
                    backup_filename = f"{hostname}_{timestamp}.swb"

                # Construct full backup path
                backup_path = os.path.join(backup_dir, backup_filename)

                # Write backup to file
                with open(backup_path, 'wb') as f:
                    f.write(backup_data)

                # Add backup path to result
                result['backup_path'] = backup_path

            except ValueError as e:
                # Switch may have default config (nothing to backup)
                # This is not a fatal error, just log it
                result['backup_warning'] = str(e)
            except Exception as e:
                # Backup failed - this is not fatal, but warn the user
                result['backup_warning'] = f"Backup failed: {str(e)}"

        # Track all changes across all sections
        all_changes = []

        # Process system configuration
        if config and 'system' in config:
            current_system = get_system_info(url, username, password)
            system_cfg = config['system']

            if not system_config_matches(current_system, system_cfg):
                change_desc = []
                if 'identity' in system_cfg and current_system.get('identity') != system_cfg['identity']:
                    change_desc.append(f"identity '{current_system.get('identity')}'->'{system_cfg['identity']}'")
                if 'address_acquisition' in system_cfg and current_system.get('address_acquisition') != system_cfg['address_acquisition']:
                    change_desc.append(f"address_acquisition {current_system.get('address_acquisition')}->{system_cfg['address_acquisition']}")
                if 'static_ip' in system_cfg and current_system.get('static_ip') != system_cfg['static_ip']:
                    change_desc.append(f"static_ip {current_system.get('static_ip')}->{system_cfg['static_ip']}")
                if 'allow_from' in system_cfg and current_system.get('allow_from') != system_cfg['allow_from']:
                    change_desc.append(f"allow_from '{current_system.get('allow_from')}'->'{system_cfg['allow_from']}'")
                if 'allow_from_ports' in system_cfg:
                    if sorted(current_system.get('allow_from_ports', [])) != sorted(system_cfg['allow_from_ports']):
                        change_desc.append(f"allow_from_ports {current_system.get('allow_from_ports')}->{system_cfg['allow_from_ports']}")
                if 'allow_from_vlan' in system_cfg and current_system.get('allow_from_vlan') != system_cfg['allow_from_vlan']:
                    change_desc.append(f"allow_from_vlan {current_system.get('allow_from_vlan')}->{system_cfg['allow_from_vlan']}")

                all_changes.append(f"System config ({', '.join(change_desc)})")

                if not module.check_mode:
                    set_system(
                        url, username, password,
                        identity=system_cfg.get('identity'),
                        address_acquisition=system_cfg.get('address_acquisition'),
                        static_ip=system_cfg.get('static_ip'),
                        allow_from=system_cfg.get('allow_from'),
                        allow_from_ports=system_cfg.get('allow_from_ports'),
                        allow_from_vlan=system_cfg.get('allow_from_vlan')
                    )

        # Process ports configuration
        if config and 'ports' in config:
            current_ports = get_links(url, username, password)
            for port_cfg in config['ports']:
                port_num = port_cfg['port']

                if port_num < 1 or port_num > len(current_ports):
                    module.fail_json(msg=f"Invalid port number: {port_num}")

                current = current_ports[port_num - 1]

                if not port_config_matches(current, port_cfg):
                    change_desc = []
                    if 'name' in port_cfg and current.get('port_name') != port_cfg['name']:
                        change_desc.append(f"name '{current.get('port_name')}'->'{port_cfg['name']}'")
                    if 'enabled' in port_cfg and current.get('enabled') != port_cfg['enabled']:
                        change_desc.append(f"enabled {current.get('enabled')}->{port_cfg['enabled']}")
                    if 'auto_negotiation' in port_cfg and current.get('auto_negotiation') != port_cfg['auto_negotiation']:
                        change_desc.append(f"auto-neg {current.get('auto_negotiation')}->{port_cfg['auto_negotiation']}")

                    all_changes.append(f"Port {port_num} config ({', '.join(change_desc)})")

                    if not module.check_mode:
                        set_port_config(
                            url, username, password, port_num,
                            name=port_cfg.get('name'),
                            enabled=port_cfg.get('enabled'),
                            auto_negotiation=port_cfg.get('auto_negotiation')
                        )

        # Process PoE configuration
        if config and 'poe' in config:
            current_poe = get_poe(url, username, password)
            for poe_cfg in config['poe']:
                # Normalize YAML booleans (off/on parsed as False/True)
                poe_cfg = normalize_poe_config(poe_cfg.copy())
                port_num = poe_cfg['port']

                if port_num < 1 or port_num > len(current_poe):
                    module.fail_json(msg=f"Invalid port number: {port_num}")

                current = current_poe[port_num - 1]

                if not poe_config_matches(current, poe_cfg):
                    change_desc = []
                    if 'mode' in poe_cfg and current.get('poe_mode') != poe_cfg['mode']:
                        change_desc.append(f"mode {current.get('poe_mode')}->{poe_cfg['mode']}")
                    if 'priority' in poe_cfg and current.get('poe_priority') != poe_cfg['priority']:
                        change_desc.append(f"priority {current.get('poe_priority')}->{poe_cfg['priority']}")
                    if 'voltage_level' in poe_cfg and current.get('voltage_level') != poe_cfg['voltage_level']:
                        change_desc.append(f"voltage {current.get('voltage_level')}->{poe_cfg['voltage_level']}")
                    if 'lldp_enabled' in poe_cfg and current.get('lldp_enabled') != poe_cfg['lldp_enabled']:
                        change_desc.append(f"LLDP {current.get('lldp_enabled')}->{poe_cfg['lldp_enabled']}")

                    all_changes.append(f"Port {port_num} PoE ({', '.join(change_desc)})")

                    if not module.check_mode:
                        set_poe_config(
                            url, username, password, port_num,
                            mode=poe_cfg.get('mode'),
                            priority=poe_cfg.get('priority'),
                            voltage_level=poe_cfg.get('voltage_level'),
                            lldp_enabled=poe_cfg.get('lldp_enabled')
                        )

        # Process LAG configuration
        if config and 'lag' in config:
            current_lag = get_lag(url, username, password)
            for lag_cfg in config['lag']:
                port_num = lag_cfg['port']

                if port_num < 1 or port_num > len(current_lag):
                    module.fail_json(msg=f"Invalid port number: {port_num}")

                current = current_lag[port_num - 1]

                if not lag_config_matches(current, lag_cfg):
                    change_desc = []
                    if 'mode' in lag_cfg and current.get('lacp_mode') != lag_cfg['mode']:
                        change_desc.append(f"mode {current.get('lacp_mode')}->{lag_cfg['mode']}")
                    if 'group' in lag_cfg and current.get('lacp_group') != lag_cfg['group']:
                        change_desc.append(f"group {current.get('lacp_group')}->{lag_cfg['group']}")

                    all_changes.append(f"Port {port_num} LAG ({', '.join(change_desc)})")

                    if not module.check_mode:
                        set_lag_config(
                            url, username, password, port_num,
                            mode=lag_cfg.get('mode'),
                            group=lag_cfg.get('group')
                        )

        # Process port VLAN configuration
        # Support both new config format and old port_vlans parameter
        if config and 'port_vlans' in config:
            port_vlans = config['port_vlans']

        if port_vlans:
            current_vlans = get_port_vlans(url, username, password)
            for port_vlan in port_vlans:
                port_num = port_vlan['port']

                if port_num < 1 or port_num > len(current_vlans):
                    module.fail_json(msg=f"Invalid port number: {port_num}")

                current = current_vlans[port_num - 1]

                if not port_vlan_matches(current, port_vlan):
                    change_desc = []
                    if 'vlan_mode' in port_vlan and current.get('vlan_mode') != port_vlan['vlan_mode']:
                        change_desc.append(f"mode {current.get('vlan_mode')}->{port_vlan['vlan_mode']}")
                    if 'vlan_receive' in port_vlan and current.get('vlan_receive') != port_vlan['vlan_receive']:
                        change_desc.append(f"receive {current.get('vlan_receive')}->{port_vlan['vlan_receive']}")
                    if 'default_vlan_id' in port_vlan and current.get('default_vlan_id') != port_vlan['default_vlan_id']:
                        change_desc.append(f"vlan {current.get('default_vlan_id')}->{port_vlan['default_vlan_id']}")
                    if 'force_vlan_id' in port_vlan and current.get('force_vlan_id') != port_vlan['force_vlan_id']:
                        change_desc.append(f"force {current.get('force_vlan_id')}->{port_vlan['force_vlan_id']}")

                    all_changes.append(f"Port {port_num} VLAN ({', '.join(change_desc)})")

                    if not module.check_mode:
                        set_port_vlan(
                            url, username, password, port_num,
                            vlan_mode=port_vlan.get('vlan_mode'),
                            vlan_receive=port_vlan.get('vlan_receive'),
                            default_vlan_id=port_vlan.get('default_vlan_id'),
                            force_vlan_id=port_vlan.get('force_vlan_id')
                        )

        # Process VLAN table configuration
        if config and 'vlans' in config:
            current_vlans = get_vlans(url, username, password)
            desired_vlans = config['vlans']

            if not vlans_match(current_vlans, desired_vlans, platform_type):
                # Build detailed change description
                current_vlan_ids = set(v['vlan_id'] for v in current_vlans)
                desired_vlan_ids = set(v['vlan_id'] for v in desired_vlans)

                added_vlans = desired_vlan_ids - current_vlan_ids
                removed_vlans = current_vlan_ids - desired_vlan_ids
                common_vlans = current_vlan_ids & desired_vlan_ids

                change_parts = []
                if added_vlans:
                    change_parts.append(f"add VLANs {sorted(added_vlans)}")
                if removed_vlans:
                    change_parts.append(f"remove VLANs {sorted(removed_vlans)}")

                # Check for changes in common VLANs
                modified_vlans = []
                current_dict = {v['vlan_id']: v for v in current_vlans}
                desired_dict = {v['vlan_id']: v for v in desired_vlans}
                for vlan_id in common_vlans:
                    curr = current_dict[vlan_id]
                    des = desired_dict[vlan_id]
                    is_modified = False

                    if sorted(curr['member_ports']) != sorted(des['member_ports']):
                        is_modified = True
                    elif curr.get('igmp_snooping', False) != des.get('igmp_snooping', False):
                        is_modified = True
                    # SwOS-only fields (skip on SwOS Lite)
                    elif not is_swos_lite(platform_type):
                        if 'name' in des and (curr.get('name') or '') != (des.get('name') or ''):
                            is_modified = True
                        elif 'isolation' in des and curr.get('isolation', False) != des['isolation']:
                            is_modified = True
                        elif 'learning' in des and curr.get('learning', True) != des['learning']:
                            is_modified = True
                        elif 'mirror' in des and curr.get('mirror', False) != des['mirror']:
                            is_modified = True

                    if is_modified:
                        modified_vlans.append(vlan_id)

                if modified_vlans:
                    change_parts.append(f"modify VLANs {sorted(modified_vlans)}")

                all_changes.append(f"VLAN table ({', '.join(change_parts)})")

                if not module.check_mode:
                    set_vlans(url, username, password, desired_vlans)

        # Process SNMP configuration
        if config and 'snmp' in config:
            current_snmp = get_snmp(url, username, password)
            snmp_cfg = config['snmp']

            if current_snmp and not snmp_config_matches(current_snmp, snmp_cfg):
                change_desc = []
                if 'enabled' in snmp_cfg and current_snmp.get('enabled') != snmp_cfg['enabled']:
                    change_desc.append(f"enabled {current_snmp.get('enabled')}->{snmp_cfg['enabled']}")
                if 'community' in snmp_cfg and current_snmp.get('community') != snmp_cfg['community']:
                    change_desc.append(f"community changed")
                if 'contact' in snmp_cfg and current_snmp.get('contact') != snmp_cfg['contact']:
                    change_desc.append(f"contact '{current_snmp.get('contact')}'->'{snmp_cfg['contact']}'")
                if 'location' in snmp_cfg and current_snmp.get('location') != snmp_cfg['location']:
                    change_desc.append(f"location '{current_snmp.get('location')}'->'{snmp_cfg['location']}'")

                all_changes.append(f"SNMP config ({', '.join(change_desc)})")

                if not module.check_mode:
                    set_snmp(
                        url, username, password,
                        enabled=snmp_cfg.get('enabled'),
                        community=snmp_cfg.get('community'),
                        contact=snmp_cfg.get('contact'),
                        location=snmp_cfg.get('location')
                    )

        # Build result message
        if all_changes:
            result['changed'] = True
            result['msg'] = f"Changed {len(all_changes)} setting(s): " + "; ".join(all_changes)
        else:
            result['msg'] = "No changes needed"

        # Get final configuration (only if changes were made)
        if not module.check_mode and result['changed']:
            result['current_config'] = {}
            if config and 'system' in config:
                result['current_config']['system'] = get_system_info(url, username, password)
            if config and 'ports' in config:
                result['current_config']['ports'] = get_links(url, username, password)
            if config and 'poe' in config:
                result['current_config']['poe'] = get_poe(url, username, password)
            if config and 'lag' in config:
                result['current_config']['lag'] = get_lag(url, username, password)
            if port_vlans:
                result['current_config']['port_vlans'] = get_port_vlans(url, username, password)
            if config and 'vlans' in config:
                result['current_config']['vlans'] = get_vlans(url, username, password)
            if config and 'snmp' in config:
                result['current_config']['snmp'] = get_snmp(url, username, password)

        module.exit_json(**result)

    except Exception as e:
        result['msg'] = f"Error: {str(e)}"
        module.fail_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()

=============================
Vyos Collection Release Notes
=============================

.. contents:: Topics


v4.1.0
======

Minor Changes
-------------

- vyos-l3_interface_support - Add support for Tunnel, Bridge and Dummy interfaces. (https://github.com/ansible-collections/vyos.vyos/issues/265)

Bugfixes
--------

- vyos-l3_interface_facts - fixed error when using no-default-link-local option. (https://github.com/ansible-collections/vyos.vyos/issues/295)

v4.0.2
======

Bugfixes
--------

- bgp_global - changed to use `neighbor.password` rather than `neighbor.address` (https://github.com/ansible-collections/vyos.vyos/issues/304).

Documentation Changes
---------------------

- vyos_interfaces - Updated documentation with examples and task output.

v4.0.1
======

Bugfixes
--------

- vyos_command - Run commands at least once even when retries is set to 0 (https://github.com/ansible-collections/cisco.nxos/issues/607).

v4.0.0
======

Major Changes
-------------

- Use of connection: local and the provider option are no longer valid on any modules in this collection.

Minor Changes
-------------

- Update fact gathering to support v1.3 show version output

Removed Features (previously deprecated)
----------------------------------------

- vyos_interface - use vyos_interfaces instead.
- vyos_l3_interface - use vyos_l3_interfaces instead.
- vyos_linkagg - use vyos_lag_interfaces instead.
- vyos_lldp - use vyos_lldp_global instead.
- vyos_lldp_interface - use vyos_lldp_interfaces instead.
- vyos_static_route - use vyos_static_routes instead.

v3.0.1
======

Minor Changes
-------------

- firewall_rules - icmpv6 type - add support for vyos sw >= 1.4.

v3.0.0
======

Major Changes
-------------

- Minimum required ansible.netcommon version is 2.5.1.
- Updated base plugin references to ansible.netcommon.
- `vyos_facts` - change default gather_subset to `min` from `!config` (https://github.com/ansible-collections/vyos.vyos/issues/231).

Minor Changes
-------------

- Change preconfig hostname from vyos to vyosuser

Bugfixes
--------

- Add symlink of modules under plugins/action

v2.8.0
======

Minor Changes
-------------

- Add vyos_hostname resource module.
- Rename V4-EGRESS/V6-EGRESS to EGRESS in the tests to test the same-name situation
- Update vyos_facts to support IPv4 and IPv6 rule sets having the same name
- Update vyos_firewall_rules to support IPv4 and IPv6 rule sets having the same name
- vyos_firewall_rules - Add support for log enable on individual rules
- vyos_firewall_rules - fixed incorrect option 'disabled' passed to the rules.

New Modules
-----------

- vyos_hostname - Manages hostname resource module

v2.7.0
======

Major Changes
-------------

- Add 'pool' as value to server key in ntp_global.

Minor Changes
-------------

- Add vyos_snmp_server resource module.

New Modules
-----------

- vyos_snmp_server - Manages snmp_server resource module

v2.6.0
======

Minor Changes
-------------

- Add vyos_ntp Resource Module
- Adds support for specifying an `afi` for an `address_group` for `vyos.vyos.firewall_global`.  As a result, `address_group` now supports IPv6.
- Adds support for specifying an `afi` for an `network_group` for `vyos.vyos.firewall_global`.  As a result, `network_group` now supports IPv6.

Bugfixes
--------

- Fix vyos_firewall_rules with state replaced to only replace the specified rules.

v2.5.1
======

Bugfixes
--------

- fix issue in firewall rules facts code when IPV6 ICMP type name in vyos.vyos.vyos_firewall_rules is not idempotent

v2.5.0
======

Minor Changes
-------------

- vyos_logging_global logging resource module.

Deprecated Features
-------------------

- The vyos_logging module has been deprecated in favor of the new vyos_logging_global resource module and will be removed in a release after "2023-08-01".

Bugfixes
--------

- fix issue in route-maps facts code when route-maps facts are empty.

v2.4.0
======

Minor Changes
-------------

- Add vyos_prefix_lists Resource Module.

New Modules
-----------

- vyos_prefix_lists - Prefix-Lists resource module for VyOS

v2.3.1
======

Bugfixes
--------

- Fix KeyError 'source' - vyos_firewall_rules
- Updated docs resolving spelling typos
- change interface to next-hop-interface while generating static_routes nexthop command.

v2.3.0
======

Minor Changes
-------------

- Add vyos_route_maps resource module (https://github.com/ansible-collections/vyos.vyos/pull/156.).

Bugfixes
--------

- change admin_distance to distance while generating static_routes nexthop command.
- firewall_global - port-groups were not added (https://github.com/ansible-collections/vyos.vyos/issues/107)

New Modules
-----------

- vyos_route_maps - Route Map Resource Module.

v2.2.0
======

Minor Changes
-------------

- Add support for available_network_resources key, which allows to fetch the available resources for a platform (https://github.com/ansible-collections/vyos.vyos/issues/138).

Security Fixes
--------------

- Mask values of sensitive keys in module result.

v2.1.0
======

Minor Changes
-------------

- Add regex for delete failures to terminal_stderr_re
- Add vyos BGP address_family resource module (https://github.com/ansible-collections/vyos.vyos/pull/132).
- Enabled addition and parsing of wireguard interface.

New Modules
-----------

- vyos_bgp_address_family - BGP Address Family Resource Module.

v2.0.0
======

Major Changes
-------------

- Please refer to ansible.netcommon `changelog <https://github.com/ansible-collections/ansible.netcommon/blob/main/changelogs/CHANGELOG.rst#ansible-netcommon-collection-release-notes>`_ for more details.
- Requires ansible.netcommon v2.0.0+ to support `ansible_network_single_user_mode` and `ansible_network_import_modules`
- ipaddress is no longer in ansible.netcommon. For Python versions without ipaddress (< 3.0), the ipaddress package is now required.

Minor Changes
-------------

- Add support for configuration caching (single_user_mode).
- Add vyos BGP global resource module.(https://github.com/ansible-collections/vyos.vyos/pull/125).
- Re-use device_info dictionary in cliconf.

Bugfixes
--------

- Update docs to clarify the idemptonecy related caveat and add it in the output warnings (https://github.com/ansible-collections/ansible.netcommon/pull/189)
- cliconf plugin - Prevent `get_capabilities()` from getting larger every time it is called

New Modules
-----------

- vyos_bgp_global - BGP Global Resource Module.

v1.1.1
======

Bugfixes
--------

- Add version key to galaxy.yaml to work around ansible-galaxy bug
- Enable configuring an interface which is not present in the running config.
- vyos_config - Only process src files as commands when they actually contain commands. This fixes an issue were the whitespace preceding a configuration key named 'set' was stripped, tripping up the parser.

v1.1.0
======

Minor Changes
-------------

- Added ospf_interfaces resource module.

New Modules
-----------

- vyos_ospf_interfaces - OSPF Interfaces Resource Module.

v1.0.5
======

Bugfixes
--------

- Added openvpn vtu interface support.
- Update network integration auth timeout for connection local.
- terminal plugin - Overhaul ansi_re to remove more escape sequences

v1.0.4
======

Minor Changes
-------------

- Moved intent testcases from integration suite to unit tests.
- Reformatted files with latest version of Black (20.8b1).

v1.0.3
======

v1.0.2
======

Minor Changes
-------------

- Fixed the typo in the modulename of ospfv2 and ospfv3 unit tests.
- Updated docs.
- terminal plugin - Added additional escape sequence to be removed from terminal output.

Bugfixes
--------

- Added workaround to avoid set_fact dynamically assigning value. This behavior seems to have been broken after ansible2.9.
- Make `src`, `backup` and `backup_options` in vyos_config work when module alias is used (https://github.com/ansible-collections/vyos.vyos/pull/67).
- vyos_config - fixed issue where config could be saved while in check mode (https://github.com/ansible-collections/vyos.vyos/pull/53)

v1.0.1
======

Minor Changes
-------------

- Add doc plugin fixes (https://github.com/ansible-collections/vyos.vyos/pull/51)

v1.0.0
======

New Plugins
-----------

Cliconf
~~~~~~~

- vyos - Use vyos cliconf to run command on VyOS platform

New Modules
-----------

- vyos_banner - Manage multiline banners on VyOS devices
- vyos_command - Run one or more commands on VyOS devices
- vyos_config - Manage VyOS configuration on remote device
- vyos_facts - Get facts about vyos devices.
- vyos_firewall_global - FIREWALL global resource module
- vyos_firewall_interfaces - FIREWALL interfaces resource module
- vyos_firewall_rules - FIREWALL rules resource module
- vyos_interfaces - Interfaces resource module
- vyos_l3_interfaces - L3 interfaces resource module
- vyos_lag_interfaces - LAG interfaces resource module
- vyos_lldp_global - LLDP global resource module
- vyos_lldp_interfaces - LLDP interfaces resource module
- vyos_logging - Manage logging on network devices
- vyos_ospfv2 - OSPFv2 resource module
- vyos_ospfv3 - OSPFV3 resource module
- vyos_ping - Tests reachability using ping from VyOS network devices
- vyos_static_routes - Static routes resource module
- vyos_system - Run `set system` commands on VyOS devices
- vyos_user - Manage the collection of local users on VyOS device
- vyos_vlan - Manage VLANs on VyOS network devices

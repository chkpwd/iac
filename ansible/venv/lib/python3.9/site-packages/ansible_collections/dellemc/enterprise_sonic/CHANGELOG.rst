======================================
Dellemc.Enterprise_Sonic Release Notes
======================================

.. contents:: Topics


v2.2.0
======

Release Summary
---------------

| Release Date: 2023-06-01
| This release provides Ansible compliance changes required on top of the changes included in
| the 2.1.0 release of the enterprise_sonic Ansible network resource module collection.
| It addresses two issues raised by the Ansible core team with the content of the 2.1.0 release.
| 1) Back out the "breaking_change" made in the sonic_aaa resource module to fix a functional
| shortcoming in the enterprise_sonic Ansible collection. Although the change is still needed,
| it will be deferred to a "major" release.
| 2) Re-enable installation of new Ansible Netcommon repo instances when installing the
| enterprise_sonic Ansible collection. The 2.1.0 enterprise_sonic Ansible release included a
| workaround for a bug introduced in the 5.0.0 version of the Ansible Netcommon repo. This
| workaround was implemented in the "galaxy.yml" file for the enterprise_sonic
| 2.1.0 release. New versions of Ansible Netcommon were published after the problematic 5.0.0
| version and the revised "galaxy.yml" file for this release enables installation of these
| newer versions.


Minor Changes
-------------

- galaxy_yml - Enable installation of Ansible Netcomon versions after 5.0.0 and update the enterprise_sonic release version (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/270).
- sonic_aaa - Revert breaking changes for AAA nodule (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/269).

v2.1.0
======

Release Summary
---------------

| Release Date: 2023-0515
| This release provides enhanced Dell Enterprise SONiC Ansible Collection support for SONiC 4.x images.
| In addition to new resource modules to support previously existing functionality, it provides
| support for the "QinQ" (Vlan Mapping) function introduced with SONiC release 4.1. It also provides
| bug fixes and enhancements for support of features that were initially introduced in previous
| Enterprise SONiC Ansible releases. The changelog describes changes made to the modules and plugins
| included in this collection since release 2.0.0.


Minor Changes
-------------

- module_utils - Change the location for importing remove_empties from the obsolete Netcommon location to the offically required Ansible library location to fix sanity errors (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/172).
- sonic_aaa - Add replaced and overridden states support for AAA resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/237).
- sonic_aaa - Add unit tests for AAA resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/198).
- sonic_api - Add unit tests for api resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/218).
- sonic_bfd, sonic_copp - Update replaced methods (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/254).
- sonic_bgp - Add rt_delay attribute to module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/244).
- sonic_bgp - Add support for replaced and overridden states (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/240).
- sonic_bgp - Add unit tests for BGP resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/182).
- sonic_bgp_af - Add several attributes to support configuration of route distinguisher and route target (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/141).
- sonic_bgp_af - Add support for replaced and overridden states (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/246).
- sonic_bgp_af - Add unit tests for BGP AF resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/183).
- sonic_bgp_af - Modify BGP AF resource module unit tests to adjust for changes in the resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/191).
- sonic_bgp_as_paths - Add unit tests for BGP AS paths resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/184).
- sonic_bgp_communities - Add unit tests for BGP communities resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/185).
- sonic_bgp_ext_communities - Add unit tests for BGP ext communities resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/186).
- sonic_bgp_neighbors - Add unit tests for BGP neighbors resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/187).
- sonic_bgp_neighbors - Enhance unit tests for BGP Neighbors resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/245).
- sonic_bgp_neighbors_af - Add unit tests for BGP neighbors AF resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/188).
- sonic_command - Add unit tests for command resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/219).
- sonic_config - Add unit tests for config resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/220).
- sonic_dhcp_relay - Add a common unit tests module and unit tests for dhcp relay module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/148).
- sonic_dhcp_relay - Add support for replaced and overridden states (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/249).
- sonic_facts - Add unit tests for facts resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/222).
- sonic_interfaces - Add speed, auto-negotiate, advertised-speed and FEC to interface resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/128).
- sonic_interfaces - Add unit tests for interfaces resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/197).
- sonic_ip_neighbor - Add unit tests for IP neighbor resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/225).
- sonic_ip_neighbor - Change the replaced function in ip_neighbor resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/253).
- sonic_l2_interfaces - Add support for parsing configuration containing the OC Yang vlan range syntax (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/124).
- sonic_l2_interfaces - Add support for replaced and overridden states (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/221).
- sonic_l2_interfaces - Add support for specifying vlan trunk ranges in Ansible playbooks (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/149).
- sonic_l2_interfaces - Add unit tests for l2_interfaces resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/200).
- sonic_l3_interfaces - Add unit tests for l3_interfaces resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/202).
- sonic_lag_interface - Add replaced and overridden states support for LAG interface resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/196).
- sonic_lag_interfaces - Add unit tests for lag_interfaces resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/203).
- sonic_logging - Add replaced and overridden states support for logging resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/150).
- sonic_logging - Add unit tests for logging resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/226).
- sonic_logging - Change logging get facts for source_interface naming (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/258).
- sonic_mclag - Add delay_restore, gateway_mac, and peer_gateway attributes to module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/145).
- sonic_ntp - Add prefer attribute to NTP resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/118).
- sonic_ntp - Add replaced and overridden states support for NTP resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/151).
- sonic_ntp - Add unit tests for NTP resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/207).
- sonic_ntp - Change NTP get facts to get default parameters (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/106).
- sonic_ntp - Change NTP key values in NTP regression test script (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/107).
- sonic_ntp - Change NTP module name (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/113).
- sonic_ntp - Change NTP module names in NTP regression test script (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/114).
- sonic_ntp - Change NTP resource module to make minpoll and maxpoll be configured together (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/129).
- sonic_port_breakout - Add unit tests for port breakout resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/229).
- sonic_port_group - Add replaced and overridden states support for port group resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/227).
- sonic_port_group - Add unit tests for port group resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/228).
- sonic_prefix_lists - Add support for replaced and overridden states (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/255).
- sonic_prefix_lists - Add unit tests for prefix lists resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/209).
- sonic_radius_server - Add replaced and overridden states support for RADIUS server resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/239).
- sonic_radius_server - Add unit tests for RADIUS server resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/210).
- sonic_static_routes - Add support for replaced and overridden states (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/236).
- sonic_static_routes - Add unit tests for static routes resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/212).
- sonic_system - Add replaced and overridden states support for system resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/159).
- sonic_system - Add unit tests for system resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/223).
- sonic_tacacs_server - Add replaced and overridden states support for TACACS server resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/235).
- sonic_tacacs_server - Add unit tests for TACACS server resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/208).
- sonic_users - Add replaced and overridden states support for users resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/242).
- sonic_users - Add unit tests for users resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/213).
- sonic_vlans - Add replaced and overridden states support for VLAN resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/217).
- sonic_vlans - Add unit tests for Vlans resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/214).
- sonic_vrfs - Add replaced and overridden states support for VRF resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/156).
- sonic_vrfs - Add unit tests for VRFS resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/216).
- sonic_vxlans - Add support for replaced and overridden states (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/247).
- sonic_vxlans - Add unit tests for VxLans resource module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/215).

Breaking Changes / Porting Guide
--------------------------------

- sonic_aaa - Add default_auth attribute to the argspec to replace the deleted group and local attributes. This change allows for ordered login authentication. (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/195).

Bugfixes
--------

- Fix regression test bugs in multiple modules (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/180).
- Fix sanity check errors in the collection caused by Ansible library changes (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/160).
- install - Update the required ansible.netcommon version (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/176).
- sonic_bgp_af - Fix issue with vnis and advertise modification for a single BGP AF (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/201).
- sonic_bgp_as_paths - Fix issues with merged and deleted states (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/250).
- sonic_interfaces - Fix command timeout issue (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/261).
- sonic_l3_interfaces - Fix IP address deletion issue (GitHub issue#170) (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/231).
- sonic_lag_interfaces - Fix port name issue (GitHub issue#153) (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/119).
- sonic_neighbors - Fix handling of default attributes (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/233).
- sonic_ntp - Fix the issue (GitHub issue#205) with NTP clear all without config given (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/224).
- sonic_vlan_mapping - Remove platform checks (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/262).
- sonic_vrfs - Add tasks as a workaround to mgmt VRF bug (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/146).
- sonic_vrfs - Fix spacing issue in CLI test case (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/257).
- sonic_vrfs - Fix the issue (GitHub issue#194) with VRF when deleting interface(https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/230).
- sonic_vxlans - Remove required_together restriction for evpn_nvo and source_ip attributes (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/130).
- workflows - Fix dependency installation issue in the code coverage workflow (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/199).

New Modules
-----------

- dellemc.enterprise_sonic.sonic_acl_interfaces - Manage access control list (ACL) to interface binding on SONiC
- dellemc.enterprise_sonic.sonic_bfd - Manage BFD configuration on SONiC
- dellemc.enterprise_sonic.sonic_copp - Manage CoPP configuration on SONiC
- dellemc.enterprise_sonic.sonic_dhcp_relay - Manage DHCP and DHCPv6 relay configurations on SONiC
- dellemc.enterprise_sonic.sonic_ip_neighbor - Manage IP neighbor global configuration on SONiC
- dellemc.enterprise_sonic.sonic_l2_acls - Manage Layer 2 access control lists (ACL) configurations on SONiC
- dellemc.enterprise_sonic.sonic_l3_acls - Manage Layer 3 access control lists (ACL) configurations on SONiC
- dellemc.enterprise_sonic.sonic_lldp_global - Manage Global LLDP configurations on SONiC
- dellemc.enterprise_sonic.sonic_logging - Manage logging configuration on SONiC
- dellemc.enterprise_sonic.sonic_mac - Manage MAC configuration on SONiC
- dellemc.enterprise_sonic.sonic_port_group - Manages port group configuration on SONiC
- dellemc.enterprise_sonic.sonic_route_maps - route map configuration handling for SONiC
- dellemc.enterprise_sonic.sonic_vlan_mapping - Configure vlan mappings on SONiC

v2.0.0
======

Release Summary
---------------

This release provides Dell SONiC Enterprise Ansible Collection support for SONiC 4.x images. It is the first release for the 2.x branch of the collection. Subsequent enhancements for support of SONiC 4.x images will also be provided as needed on the 2.x branch. This release also contains bugfixes and enhancements to supplement the Ansible functionality provided previously for SONiC 3.x images. The changelog describes changes made to the modules and plugins included in this collection since release 1.1.0.


Minor Changes
-------------

- Add an execution-environment.yml file to the "meta" directory to enable use of Ansible execution environment infrastructure (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/88).
- bgp_af - Add support for BGP options to configure usage and advertisement of vxlan primary IP address related attributes (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/62).
- bgp_as_paths - Update module examples with 'permit' attribute (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/102).
- bgp_neighbors - Add BGP peer group support for multiple attributes. The added attributes correspond to the same set of attributes added for BGP neighbors with PR 72 (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/81).
- bgp_neighbors - Add an auth_pwd dictionary and nbr_description attribute to the argspec (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/67).
- bgp_neighbors - Add prefix-list related peer-group attributes (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/101).
- bgp_neighbors - Add support for multiple attributes (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/72).
- bgp_neighbors_af - Add prefix-list related neighbor attributes (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/101).
- playbook - Update examples to reflect module changes (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/102).
- sonic_vxlans - Add configuration capability for the primary IP address of a vxlan vtep to facilitate vxlan path redundundancy (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/58).
- vlans - Add support for the vlan "description" attribute (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/98).
- workflow - Add stable-2.13 to the sanity test matrix (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/90).

Breaking Changes / Porting Guide
--------------------------------

- bgp_af - Add the route_advertise_list dictionary to the argspec to replace the deleted, obsolete advertise_prefix attribute used for SONiC 3.x images on the 1.x branch of this collection. This change corresponds to a SONiC 4.0 OC YANG REST compliance change for the BGP AF REST API. It enables specification of a route map in conjunction with each route advertisement prefix (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/63).
- bgp_af - Remove the obsolete 'advertise_prefix' attribute from argspec and config code. This and subsequent co-req replacement with the new route advertise list argument structure require corresponding changes in playbooks previoulsly used for configuring route advertise prefixes for SONiC 3.x images. (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/60).
- bgp_neighbors - Replace the previously defined standalone "bfd" attribute with a bfd dictionary containing multiple attributes. This change corresponds to the revised SONiC 4.x implementation of OC YANG compatible REST APIs. Playbooks previously using the bfd attributes for SONiC 3.x images must be modified for use on SONiC 4.0 images to use the new definition for the bfd attribute argspec structure (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/72).
- bgp_neighbors - Replace, for BGP peer groups, the previously defined standalone "bfd" attribute with a bfd dictionary containing multiple attributes. This change corresponds to the revised SONiC 4.x implementation of OC YANG compatible REST APIs. Playbooks previously using the bfd attributes for SONiC 3.x images must be modified for use on SONiC 4.0 images to use the new definition for the bfd attribute argspec structure (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/81).

Bugfixes
--------

- Fixed regression test bugs in multiple modules (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/103).
- Fixed regression test sequencing and other regression test bugs in multiple modules (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/85).
- bgp_neighbors - Remove string conversion of timer attributes (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/60).
- port_breakout - Fixed a bug in formulation of port breakout REST APIs (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/88).
- sonic - Fix a bug in handling of interface names in standard interface naming mode (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/103).
- sonic_aaa - Fix a bug in facts gathering by providing required conditional branching (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/90).
- sonic_aaa - Modify regression test sequencing to enable correct testing of the functionality for this module (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/78).
- sonic_command - Fix bugs in handling of CLI commands involving a prompt and answer sequence (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/76/files).
- users - Fixed a bug in facts gathering (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/90).
- vxlan - update Vxlan test cases to comply with SONiC behavior (https://github.com/ansible-collections/dellemc.enterprise_sonic/pull/105).

New Modules
-----------

- dellemc.enterprise_sonic.sonic_ntp - Manage NTP configuration on SONiC.
- dellemc.enterprise_sonic.sonic_prefix_lists - prefix list configuration handling for SONiC
- dellemc.enterprise_sonic.sonic_static_routes - Manage static routes configuration on SONiC

v1.1.0
======

New Modules
-----------

- dellemc.enterprise_sonic.sonic_aaa - Manage AAA and its parameters
- dellemc.enterprise_sonic.sonic_radius_server - Manage RADIUS server and its parameters
- dellemc.enterprise_sonic.sonic_system - Configure system parameters
- dellemc.enterprise_sonic.sonic_tacacs_server - Manage TACACS server and its parameters

v1.0.0
======

New Plugins
-----------

Cliconf
~~~~~~~

- dellemc.enterprise_sonic.sonic - Use sonic cliconf to run command on Dell OS10 platform

Httpapi
~~~~~~~

- dellemc.enterprise_sonic.sonic - HttpApi Plugin for devices supporting Restconf SONIC API

New Modules
-----------

- dellemc.enterprise_sonic.sonic_api - Manages REST operations on devices running Enterprise SONiC
- dellemc.enterprise_sonic.sonic_bgp - Manage global BGP and its parameters
- dellemc.enterprise_sonic.sonic_bgp_af - Manage global BGP address-family and its parameters
- dellemc.enterprise_sonic.sonic_bgp_as_paths - Manage BGP autonomous system path (or as-path-list) and its parameters
- dellemc.enterprise_sonic.sonic_bgp_communities - Manage BGP community and its parameters
- dellemc.enterprise_sonic.sonic_bgp_ext_communities - Manage BGP extended community-list and its parameters
- dellemc.enterprise_sonic.sonic_bgp_neighbors - Manage a BGP neighbor and its parameters
- dellemc.enterprise_sonic.sonic_bgp_neighbors_af - Manage the BGP neighbor address-family and its parameters
- dellemc.enterprise_sonic.sonic_command - Runs commands on devices running Enterprise SONiC
- dellemc.enterprise_sonic.sonic_config - Manages configuration sections on devices running Enterprise SONiC
- dellemc.enterprise_sonic.sonic_interfaces - Configure Interface attributes on interfaces such as, Eth, LAG, VLAN, and loopback. (create a loopback interface if it does not exist.)
- dellemc.enterprise_sonic.sonic_l2_interfaces - Configure interface-to-VLAN association that is based on access or trunk mode
- dellemc.enterprise_sonic.sonic_l3_interfaces - Configure the IPv4 and IPv6 parameters on Interfaces such as, Eth, LAG, VLAN, and loopback
- dellemc.enterprise_sonic.sonic_lag_interfaces - Manage link aggregation group (LAG) interface parameters
- dellemc.enterprise_sonic.sonic_mclag - Manage multi chassis link aggregation groups domain (MCLAG) and its parameters
- dellemc.enterprise_sonic.sonic_port_breakout - Configure port breakout settings on physical interfaces
- dellemc.enterprise_sonic.sonic_users - Manage users and its parameters
- dellemc.enterprise_sonic.sonic_vlans - Manage VLAN and its parameters
- dellemc.enterprise_sonic.sonic_vrfs - Manage VRFs and associate VRFs to interfaces such as, Eth, LAG, VLAN, and loopback
- dellemc.enterprise_sonic.sonic_vxlans - Manage VxLAN EVPN and its parameters

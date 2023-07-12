===================================
Fortinet.Fortimanager Release Notes
===================================

.. contents:: Topics


v2.2.0
======

Release Summary
---------------

release fortinet.fortimanager to support FMG v6.0 - v7.4.

Major Changes
-------------

- Support all FortiManager versions in 6.2, 6.4, 7.0, 7.2 and 7.4. 139 new modules.
- Support token based authentication.

Minor Changes
-------------

- Corrected the behavior of module fmgr_pkg_firewall_consolidated_policy_sectionvalue and fmgr_pkg_firewall_securitypolicy_sectionvalue.
- Improve documentation.

Bugfixes
--------

- Corrected description of parameters in documentation.
- Fixed Many sanity test warnings and errors.
- Fixed a bug where users might not be able to log in.
- Fixed version_added in the document. The value of this parameter is the version each module first supported in the FortiManager Ansible Collection.

New Modules
-----------

- fortinet.fortimanager.fmgr_application_casi_profile - Cloud Access Security Inspection.
- fortinet.fortimanager.fmgr_application_casi_profile_entries - Application entries.
- fortinet.fortimanager.fmgr_application_internetservice - Show Internet service application.
- fortinet.fortimanager.fmgr_application_internetservice_entry - Entries in the Internet service database.
- fortinet.fortimanager.fmgr_application_internetservicecustom - Configure custom Internet service applications.
- fortinet.fortimanager.fmgr_application_internetservicecustom_disableentry - Disable entries in the Internet service database.
- fortinet.fortimanager.fmgr_application_internetservicecustom_disableentry_iprange - IP ranges in the disable entry.
- fortinet.fortimanager.fmgr_application_internetservicecustom_entry - Entries added to the Internet service database and custom database.
- fortinet.fortimanager.fmgr_application_internetservicecustom_entry_portrange - Port ranges in the custom entry.
- fortinet.fortimanager.fmgr_cloud_orchestaws - no description
- fortinet.fortimanager.fmgr_cloud_orchestawsconnector - no description
- fortinet.fortimanager.fmgr_cloud_orchestawstemplate_autoscaleexistingvpc - no description
- fortinet.fortimanager.fmgr_cloud_orchestawstemplate_autoscalenewvpc - no description
- fortinet.fortimanager.fmgr_cloud_orchestawstemplate_autoscaletgwnewvpc - no description
- fortinet.fortimanager.fmgr_cloud_orchestration - no description
- fortinet.fortimanager.fmgr_devprof_log_syslogd_filter_excludelist - no description
- fortinet.fortimanager.fmgr_devprof_log_syslogd_filter_excludelist_fields - no description
- fortinet.fortimanager.fmgr_devprof_log_syslogd_filter_freestyle - Free style filters.
- fortinet.fortimanager.fmgr_devprof_log_syslogd_setting_customfieldname - Custom field name for CEF format logging.
- fortinet.fortimanager.fmgr_dnsfilter_profile_urlfilter - URL filter settings.
- fortinet.fortimanager.fmgr_dnsfilter_urlfilter - Configure URL filter list.
- fortinet.fortimanager.fmgr_dnsfilter_urlfilter_entries - DNS URL filter.
- fortinet.fortimanager.fmgr_emailfilter_profile_yahoomail - Yahoo! Mail.
- fortinet.fortimanager.fmgr_extensioncontroller_dataplan - FortiExtender dataplan configuration.
- fortinet.fortimanager.fmgr_extensioncontroller_extenderprofile - FortiExtender extender profile configuration.
- fortinet.fortimanager.fmgr_extensioncontroller_extenderprofile_cellular - FortiExtender cellular configuration.
- fortinet.fortimanager.fmgr_extensioncontroller_extenderprofile_cellular_controllerreport - FortiExtender controller report configuration.
- fortinet.fortimanager.fmgr_extensioncontroller_extenderprofile_cellular_modem1 - Configuration options for modem 1.
- fortinet.fortimanager.fmgr_extensioncontroller_extenderprofile_cellular_modem1_autoswitch - FortiExtender auto switch configuration.
- fortinet.fortimanager.fmgr_extensioncontroller_extenderprofile_cellular_modem2 - Configuration options for modem 2.
- fortinet.fortimanager.fmgr_extensioncontroller_extenderprofile_cellular_modem2_autoswitch - FortiExtender auto switch configuration.
- fortinet.fortimanager.fmgr_extensioncontroller_extenderprofile_cellular_smsnotification - FortiExtender cellular SMS notification configuration.
- fortinet.fortimanager.fmgr_extensioncontroller_extenderprofile_cellular_smsnotification_alert - SMS alert list.
- fortinet.fortimanager.fmgr_extensioncontroller_extenderprofile_cellular_smsnotification_receiver - SMS notification receiver list.
- fortinet.fortimanager.fmgr_extensioncontroller_extenderprofile_lanextension - FortiExtender lan extension configuration.
- fortinet.fortimanager.fmgr_extensioncontroller_extenderprofile_lanextension_backhaul - LAN extension backhaul tunnel configuration.
- fortinet.fortimanager.fmgr_firewall_accessproxy6 - Configure IPv6 access proxy.
- fortinet.fortimanager.fmgr_firewall_accessproxy6_apigateway - Set IPv4 API Gateway.
- fortinet.fortimanager.fmgr_firewall_accessproxy6_apigateway6 - Set IPv6 API Gateway.
- fortinet.fortimanager.fmgr_firewall_accessproxy6_apigateway6_realservers - Select the real servers that this Access Proxy will distribute traffic to.
- fortinet.fortimanager.fmgr_firewall_accessproxy6_apigateway6_sslciphersuites - SSL/TLS cipher suites to offer to a server, ordered by priority.
- fortinet.fortimanager.fmgr_firewall_accessproxy6_apigateway_realservers - Select the real servers that this Access Proxy will distribute traffic to.
- fortinet.fortimanager.fmgr_firewall_accessproxy6_apigateway_sslciphersuites - SSL/TLS cipher suites to offer to a server, ordered by priority.
- fortinet.fortimanager.fmgr_firewall_address6_profilelist - List of NSX service profiles that use this address.
- fortinet.fortimanager.fmgr_firewall_address_profilelist - List of NSX service profiles that use this address.
- fortinet.fortimanager.fmgr_firewall_explicitproxyaddress - Explicit web proxy address configuration.
- fortinet.fortimanager.fmgr_firewall_explicitproxyaddress_headergroup - HTTP header group.
- fortinet.fortimanager.fmgr_firewall_explicitproxyaddrgrp - Explicit web proxy address group configuration.
- fortinet.fortimanager.fmgr_firewall_gtp_messagefilter - Message filter.
- fortinet.fortimanager.fmgr_firewall_ippoolgrp - Configure IPv4 pool groups.
- fortinet.fortimanager.fmgr_firewall_networkservicedynamic - Configure Dynamic Network Services.
- fortinet.fortimanager.fmgr_fmg_fabric_authorization_template - no description
- fortinet.fortimanager.fmgr_fmg_fabric_authorization_template_platforms - no description
- fortinet.fortimanager.fmgr_fmupdate_fwmsetting_upgradetimeout - Configure the timeout value of image upgrade process.
- fortinet.fortimanager.fmgr_fsp_vlan_dynamicmapping_interface_vrrp - VRRP configuration.
- fortinet.fortimanager.fmgr_fsp_vlan_dynamicmapping_interface_vrrp_proxyarp - VRRP Proxy ARP configuration.
- fortinet.fortimanager.fmgr_fsp_vlan_interface_vrrp_proxyarp - VRRP Proxy ARP configuration.
- fortinet.fortimanager.fmgr_ips_baseline_sensor - Configure IPS sensor.
- fortinet.fortimanager.fmgr_ips_baseline_sensor_entries - IPS sensor filter.
- fortinet.fortimanager.fmgr_ips_baseline_sensor_entries_exemptip - Traffic from selected source or destination IP addresses is exempt from this signature.
- fortinet.fortimanager.fmgr_ips_baseline_sensor_filter - no description
- fortinet.fortimanager.fmgr_ips_baseline_sensor_override - no description
- fortinet.fortimanager.fmgr_ips_baseline_sensor_override_exemptip - no description
- fortinet.fortimanager.fmgr_log_npuserver - Configure all the log servers and create the server groups.
- fortinet.fortimanager.fmgr_log_npuserver_servergroup - create server group.
- fortinet.fortimanager.fmgr_log_npuserver_serverinfo - configure server info.
- fortinet.fortimanager.fmgr_pkg_firewall_explicitproxypolicy - Configure Explicit proxy policies.
- fortinet.fortimanager.fmgr_pkg_firewall_explicitproxypolicy_identitybasedpolicy - Identity-based policy.
- fortinet.fortimanager.fmgr_pkg_firewall_explicitproxypolicy_sectionvalue - Configure Explicit proxy policies.
- fortinet.fortimanager.fmgr_pkg_firewall_hyperscalepolicy - Configure IPv4/IPv6 policies.
- fortinet.fortimanager.fmgr_pkg_firewall_hyperscalepolicy46 - Configure IPv4 to IPv6 policies.
- fortinet.fortimanager.fmgr_pkg_firewall_hyperscalepolicy6 - Configure IPv6 policies.
- fortinet.fortimanager.fmgr_pkg_firewall_hyperscalepolicy64 - Configure IPv6 to IPv4 policies.
- fortinet.fortimanager.fmgr_pkg_user_nacpolicy - Configure NAC policy matching pattern to identify matching NAC devices.
- fortinet.fortimanager.fmgr_pm_config_pblock_firewall_consolidated_policy - Configure consolidated IPv4/IPv6 policies.
- fortinet.fortimanager.fmgr_pm_config_pblock_firewall_consolidated_policy_sectionvalue - Configure consolidated IPv4/IPv6 policies.
- fortinet.fortimanager.fmgr_pm_config_pblock_firewall_policy6 - Configure IPv6 policies.
- fortinet.fortimanager.fmgr_pm_config_pblock_firewall_policy6_sectionvalue - Configure IPv6 policies.
- fortinet.fortimanager.fmgr_pm_devprof_scopemember - no description
- fortinet.fortimanager.fmgr_pm_pkg_scopemember - Policy package or folder.
- fortinet.fortimanager.fmgr_pm_wanprof_scopemember - no description
- fortinet.fortimanager.fmgr_securityconsole_template_cli_preview - no description
- fortinet.fortimanager.fmgr_switchcontroller_acl_group - Configure ACL groups to be applied on managed FortiSwitch ports.
- fortinet.fortimanager.fmgr_switchcontroller_acl_ingress - Configure ingress ACL policies to be applied on managed FortiSwitch ports.
- fortinet.fortimanager.fmgr_switchcontroller_acl_ingress_action - ACL actions.
- fortinet.fortimanager.fmgr_switchcontroller_acl_ingress_classifier - ACL classifiers.
- fortinet.fortimanager.fmgr_switchcontroller_dynamicportpolicy - Configure Dynamic port policy to be applied on the managed FortiSwitch ports through DPP device.
- fortinet.fortimanager.fmgr_switchcontroller_dynamicportpolicy_policy - Port policies with matching criteria and actions.
- fortinet.fortimanager.fmgr_switchcontroller_fortilinksettings - Configure integrated FortiLink settings for FortiSwitch.
- fortinet.fortimanager.fmgr_switchcontroller_fortilinksettings_nacports - NAC specific configuration.
- fortinet.fortimanager.fmgr_switchcontroller_macpolicy - Configure MAC policy to be applied on the managed FortiSwitch devices through NAC device.
- fortinet.fortimanager.fmgr_switchcontroller_managedswitch_dhcpsnoopingstaticclient - Configure FortiSwitch DHCP snooping static clients.
- fortinet.fortimanager.fmgr_switchcontroller_managedswitch_ports_dhcpsnoopoption82override - Configure DHCP snooping option 82 override.
- fortinet.fortimanager.fmgr_switchcontroller_managedswitch_staticmac - Configuration method to edit FortiSwitch Static and Sticky MAC.
- fortinet.fortimanager.fmgr_switchcontroller_managedswitch_stpinstance - Configuration method to edit Spanning Tree Protocol
- fortinet.fortimanager.fmgr_switchcontroller_switchinterfacetag - Configure switch object tags.
- fortinet.fortimanager.fmgr_switchcontroller_trafficpolicy - Configure FortiSwitch traffic policy.
- fortinet.fortimanager.fmgr_switchcontroller_vlanpolicy - Configure VLAN policy to be applied on the managed FortiSwitch ports through dynamic-port-policy.
- fortinet.fortimanager.fmgr_sys_cloud_orchest - no description
- fortinet.fortimanager.fmgr_system_npu_backgroundssescan - Configure driver background scan for SSE.
- fortinet.fortimanager.fmgr_system_npu_dosoptions - NPU DoS configurations.
- fortinet.fortimanager.fmgr_system_npu_dswdtsprofile - Configure NPU DSW DTS profile.
- fortinet.fortimanager.fmgr_system_npu_dswqueuedtsprofile - Configure NPU DSW Queue DTS profile.
- fortinet.fortimanager.fmgr_system_npu_hpe - Host protection engine configuration.
- fortinet.fortimanager.fmgr_system_npu_ipreassembly - IP reassebmly engine configuration.
- fortinet.fortimanager.fmgr_system_npu_npqueues - Configure queue assignment on NP7.
- fortinet.fortimanager.fmgr_system_npu_npqueues_ethernettype - Configure a NP7 QoS Ethernet Type.
- fortinet.fortimanager.fmgr_system_npu_npqueues_ipprotocol - Configure a NP7 QoS IP Protocol.
- fortinet.fortimanager.fmgr_system_npu_npqueues_ipservice - Configure a NP7 QoS IP Service.
- fortinet.fortimanager.fmgr_system_npu_npqueues_profile - Configure a NP7 class profile.
- fortinet.fortimanager.fmgr_system_npu_npqueues_scheduler - Configure a NP7 QoS Scheduler.
- fortinet.fortimanager.fmgr_system_npu_portpathoption - Configure port using NPU or Intel-NIC.
- fortinet.fortimanager.fmgr_system_npu_ssehascan - Configure driver HA scan for SSE.
- fortinet.fortimanager.fmgr_system_npu_swtrhash - Configure switch traditional hashing.
- fortinet.fortimanager.fmgr_system_npu_tcptimeoutprofile - Configure TCP timeout profile.
- fortinet.fortimanager.fmgr_system_npu_udptimeoutprofile - Configure UDP timeout profile.
- fortinet.fortimanager.fmgr_system_objecttag - Configure object tags.
- fortinet.fortimanager.fmgr_system_sdnconnector_compartmentlist - Configure OCI compartment list.
- fortinet.fortimanager.fmgr_system_sdnconnector_ociregionlist - Configure OCI region list.
- fortinet.fortimanager.fmgr_system_socfabric_trustedlist - Pre-authorized security fabric nodes
- fortinet.fortimanager.fmgr_um_image_upgrade - The older API for updating the firmware of specific device.
- fortinet.fortimanager.fmgr_um_image_upgrade_ext - Update the firmware of specific device.
- fortinet.fortimanager.fmgr_user_certificate - Configure certificate users.
- fortinet.fortimanager.fmgr_user_deviceaccesslist - Configure device access control lists.
- fortinet.fortimanager.fmgr_user_deviceaccesslist_devicelist - Device list.
- fortinet.fortimanager.fmgr_user_flexvm - no description
- fortinet.fortimanager.fmgr_user_json - no description
- fortinet.fortimanager.fmgr_user_saml_dynamicmapping - SAML server entry configuration.
- fortinet.fortimanager.fmgr_vpnsslweb_portal_landingpage - Landing page options.
- fortinet.fortimanager.fmgr_vpnsslweb_portal_landingpage_formdata - Form data.
- fortinet.fortimanager.fmgr_vpnsslweb_virtualdesktopapplist - SSL-VPN virtual desktop application list.
- fortinet.fortimanager.fmgr_vpnsslweb_virtualdesktopapplist_apps - Applications.
- fortinet.fortimanager.fmgr_wireless_accesscontrollist - Configure WiFi bridge access control list.
- fortinet.fortimanager.fmgr_wireless_accesscontrollist_layer3ipv4rules - AP ACL layer3 ipv4 rule list.
- fortinet.fortimanager.fmgr_wireless_accesscontrollist_layer3ipv6rules - AP ACL layer3 ipv6 rule list.
- fortinet.fortimanager.fmgr_wireless_address - Configure the client with its MAC address.
- fortinet.fortimanager.fmgr_wireless_addrgrp - Configure the MAC address group.
- fortinet.fortimanager.fmgr_wireless_ssidpolicy - Configure WiFi SSID policies.
- fortinet.fortimanager.fmgr_wireless_syslogprofile - Configure Wireless Termination Points

v2.1.7
======

Release Summary
---------------

hotpath for backward-compatibility fix

Major Changes
-------------

- Fix compatibility issue for ansible 2.9.x and ansible-base 2.10.x.
- support Ansible changelogs.

v2.1.6
======

Release Summary
---------------

release fortinet.fortimanager to support FMG 7.2.x

Major Changes
-------------

- Many fixes for Ansible sanity test warnings & errors.
- Support FortiManager Schema 7.2.0 , 98 new modules

Minor Changes
-------------

- Best Practice Notes

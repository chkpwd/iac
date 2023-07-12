#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2020-2023 Fortinet, Inc.
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
module: fmgr_clone
short_description: Clone an object in FortiManager.
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
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        required: false
        type: str
    enable_log:
        description: Enable/Disable logging for task.
        required: false
        type: bool
        default: false
    forticloud_access_token:
        description: Access token of FortiCloud managed API users, this option is available with FortiManager later than 6.4.0.
        required: false
        type: str
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        required: false
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other users to release workspace lock.
        required: false
        type: int
        default: 300
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
    clone:
        description: Clone An Object.
        type: dict
        required: true
        suboptions:
            selector:
                required: true
                description: Selector of the clone object.
                type: str
                choices:
                    - 'antivirus_mmschecksum'
                    - 'antivirus_mmschecksum_entries'
                    - 'antivirus_notification'
                    - 'antivirus_notification_entries'
                    - 'antivirus_profile'
                    - 'apcfgprofile'
                    - 'apcfgprofile_commandlist'
                    - 'application_casi_profile'
                    - 'application_casi_profile_entries'
                    - 'application_categories'
                    - 'application_custom'
                    - 'application_group'
                    - 'application_internetservice_entry'
                    - 'application_internetservicecustom'
                    - 'application_internetservicecustom_disableentry'
                    - 'application_internetservicecustom_disableentry_iprange'
                    - 'application_internetservicecustom_entry'
                    - 'application_internetservicecustom_entry_portrange'
                    - 'application_list'
                    - 'application_list_defaultnetworkservices'
                    - 'application_list_entries'
                    - 'application_list_entries_parameters'
                    - 'application_list_entries_parameters_members'
                    - 'arrpprofile'
                    - 'authentication_scheme'
                    - 'bleprofile'
                    - 'bonjourprofile'
                    - 'bonjourprofile_policylist'
                    - 'certificate_template'
                    - 'cifs_domaincontroller'
                    - 'cifs_profile'
                    - 'cifs_profile_filefilter_entries'
                    - 'cifs_profile_serverkeytab'
                    - 'cloud_orchestaws'
                    - 'cloud_orchestawsconnector'
                    - 'cloud_orchestawstemplate_autoscaleexistingvpc'
                    - 'cloud_orchestawstemplate_autoscalenewvpc'
                    - 'cloud_orchestawstemplate_autoscaletgwnewvpc'
                    - 'cloud_orchestration'
                    - 'credentialstore_domaincontroller'
                    - 'devprof_log_syslogd_filter_excludelist'
                    - 'devprof_log_syslogd_filter_excludelist_fields'
                    - 'devprof_log_syslogd_filter_freestyle'
                    - 'devprof_log_syslogd_setting_customfieldname'
                    - 'devprof_system_centralmanagement_serverlist'
                    - 'devprof_system_ntp_ntpserver'
                    - 'devprof_system_snmp_community'
                    - 'devprof_system_snmp_community_hosts'
                    - 'devprof_system_snmp_community_hosts6'
                    - 'devprof_system_snmp_user'
                    - 'dlp_datatype'
                    - 'dlp_dictionary'
                    - 'dlp_dictionary_entries'
                    - 'dlp_filepattern'
                    - 'dlp_filepattern_entries'
                    - 'dlp_fpsensitivity'
                    - 'dlp_profile'
                    - 'dlp_profile_rule'
                    - 'dlp_sensitivity'
                    - 'dlp_sensor'
                    - 'dlp_sensor_entries'
                    - 'dlp_sensor_filter'
                    - 'dnsfilter_domainfilter'
                    - 'dnsfilter_domainfilter_entries'
                    - 'dnsfilter_profile'
                    - 'dnsfilter_profile_dnstranslation'
                    - 'dnsfilter_profile_ftgddns_filters'
                    - 'dnsfilter_urlfilter'
                    - 'dnsfilter_urlfilter_entries'
                    - 'dvmdb_revision'
                    - 'dynamic_address'
                    - 'dynamic_address_dynamicaddrmapping'
                    - 'dynamic_certificate_local'
                    - 'dynamic_certificate_local_dynamicmapping'
                    - 'dynamic_input_interface'
                    - 'dynamic_input_interface_dynamicmapping'
                    - 'dynamic_interface'
                    - 'dynamic_interface_dynamicmapping'
                    - 'dynamic_interface_platformmapping'
                    - 'dynamic_ippool'
                    - 'dynamic_multicast_interface'
                    - 'dynamic_multicast_interface_dynamicmapping'
                    - 'dynamic_vip'
                    - 'dynamic_virtualwanlink_members'
                    - 'dynamic_virtualwanlink_members_dynamicmapping'
                    - 'dynamic_virtualwanlink_neighbor'
                    - 'dynamic_virtualwanlink_neighbor_dynamicmapping'
                    - 'dynamic_virtualwanlink_server'
                    - 'dynamic_virtualwanlink_server_dynamicmapping'
                    - 'dynamic_vpntunnel'
                    - 'dynamic_vpntunnel_dynamicmapping'
                    - 'emailfilter_blockallowlist'
                    - 'emailfilter_blockallowlist_entries'
                    - 'emailfilter_bwl'
                    - 'emailfilter_bwl_entries'
                    - 'emailfilter_bword'
                    - 'emailfilter_bword_entries'
                    - 'emailfilter_dnsbl'
                    - 'emailfilter_dnsbl_entries'
                    - 'emailfilter_iptrust'
                    - 'emailfilter_iptrust_entries'
                    - 'emailfilter_mheader'
                    - 'emailfilter_mheader_entries'
                    - 'emailfilter_profile'
                    - 'emailfilter_profile_filefilter_entries'
                    - 'endpointcontrol_fctems'
                    - 'extendercontroller_dataplan'
                    - 'extendercontroller_extenderprofile'
                    - 'extendercontroller_extenderprofile_cellular_smsnotification_receiver'
                    - 'extendercontroller_extenderprofile_lanextension_backhaul'
                    - 'extendercontroller_simprofile'
                    - 'extendercontroller_template'
                    - 'extensioncontroller_dataplan'
                    - 'extensioncontroller_extenderprofile'
                    - 'extensioncontroller_extenderprofile_cellular_smsnotification_receiver'
                    - 'extensioncontroller_extenderprofile_lanextension_backhaul'
                    - 'filefilter_profile'
                    - 'filefilter_profile_rules'
                    - 'firewall_accessproxy'
                    - 'firewall_accessproxy6'
                    - 'firewall_accessproxy6_apigateway'
                    - 'firewall_accessproxy6_apigateway6'
                    - 'firewall_accessproxy6_apigateway6_realservers'
                    - 'firewall_accessproxy6_apigateway6_sslciphersuites'
                    - 'firewall_accessproxy6_apigateway_realservers'
                    - 'firewall_accessproxy6_apigateway_sslciphersuites'
                    - 'firewall_accessproxy_apigateway'
                    - 'firewall_accessproxy_apigateway6'
                    - 'firewall_accessproxy_apigateway6_realservers'
                    - 'firewall_accessproxy_apigateway6_sslciphersuites'
                    - 'firewall_accessproxy_apigateway_realservers'
                    - 'firewall_accessproxy_apigateway_sslciphersuites'
                    - 'firewall_accessproxy_realservers'
                    - 'firewall_accessproxy_serverpubkeyauthsettings_certextension'
                    - 'firewall_accessproxyvirtualhost'
                    - 'firewall_address'
                    - 'firewall_address6'
                    - 'firewall_address6_dynamicmapping'
                    - 'firewall_address6_dynamicmapping_subnetsegment'
                    - 'firewall_address6_list'
                    - 'firewall_address6_profilelist'
                    - 'firewall_address6_subnetsegment'
                    - 'firewall_address6_tagging'
                    - 'firewall_address6template'
                    - 'firewall_address6template_subnetsegment'
                    - 'firewall_address6template_subnetsegment_values'
                    - 'firewall_address_dynamicmapping'
                    - 'firewall_address_list'
                    - 'firewall_address_profilelist'
                    - 'firewall_address_tagging'
                    - 'firewall_addrgrp'
                    - 'firewall_addrgrp6'
                    - 'firewall_addrgrp6_dynamicmapping'
                    - 'firewall_addrgrp6_tagging'
                    - 'firewall_addrgrp_dynamicmapping'
                    - 'firewall_addrgrp_tagging'
                    - 'firewall_carrierendpointbwl'
                    - 'firewall_carrierendpointbwl_entries'
                    - 'firewall_decryptedtrafficmirror'
                    - 'firewall_explicitproxyaddress'
                    - 'firewall_explicitproxyaddress_headergroup'
                    - 'firewall_explicitproxyaddrgrp'
                    - 'firewall_gtp'
                    - 'firewall_gtp_apn'
                    - 'firewall_gtp_ieremovepolicy'
                    - 'firewall_gtp_imsi'
                    - 'firewall_gtp_ippolicy'
                    - 'firewall_gtp_noippolicy'
                    - 'firewall_gtp_perapnshaper'
                    - 'firewall_gtp_policy'
                    - 'firewall_gtp_policyv2'
                    - 'firewall_identitybasedroute'
                    - 'firewall_identitybasedroute_rule'
                    - 'firewall_internetservice_entry'
                    - 'firewall_internetserviceaddition'
                    - 'firewall_internetserviceaddition_entry'
                    - 'firewall_internetserviceaddition_entry_portrange'
                    - 'firewall_internetservicecustom'
                    - 'firewall_internetservicecustom_disableentry'
                    - 'firewall_internetservicecustom_disableentry_iprange'
                    - 'firewall_internetservicecustom_entry'
                    - 'firewall_internetservicecustom_entry_portrange'
                    - 'firewall_internetservicecustomgroup'
                    - 'firewall_internetservicegroup'
                    - 'firewall_internetservicename'
                    - 'firewall_ippool'
                    - 'firewall_ippool6'
                    - 'firewall_ippool6_dynamicmapping'
                    - 'firewall_ippool_dynamicmapping'
                    - 'firewall_ippoolgrp'
                    - 'firewall_ldbmonitor'
                    - 'firewall_mmsprofile'
                    - 'firewall_mmsprofile_notifmsisdn'
                    - 'firewall_multicastaddress'
                    - 'firewall_multicastaddress6'
                    - 'firewall_multicastaddress6_tagging'
                    - 'firewall_multicastaddress_tagging'
                    - 'firewall_networkservicedynamic'
                    - 'firewall_profilegroup'
                    - 'firewall_profileprotocoloptions'
                    - 'firewall_profileprotocoloptions_cifs_filefilter_entries'
                    - 'firewall_profileprotocoloptions_cifs_serverkeytab'
                    - 'firewall_proxyaddress'
                    - 'firewall_proxyaddress_headergroup'
                    - 'firewall_proxyaddress_tagging'
                    - 'firewall_proxyaddrgrp'
                    - 'firewall_proxyaddrgrp_tagging'
                    - 'firewall_schedule_group'
                    - 'firewall_schedule_onetime'
                    - 'firewall_schedule_recurring'
                    - 'firewall_service_category'
                    - 'firewall_service_custom'
                    - 'firewall_service_group'
                    - 'firewall_shaper_peripshaper'
                    - 'firewall_shaper_trafficshaper'
                    - 'firewall_shapingprofile'
                    - 'firewall_shapingprofile_shapingentries'
                    - 'firewall_ssh_localca'
                    - 'firewall_sslsshprofile'
                    - 'firewall_sslsshprofile_sslexempt'
                    - 'firewall_sslsshprofile_sslserver'
                    - 'firewall_trafficclass'
                    - 'firewall_vip'
                    - 'firewall_vip46'
                    - 'firewall_vip46_dynamicmapping'
                    - 'firewall_vip46_realservers'
                    - 'firewall_vip6'
                    - 'firewall_vip64'
                    - 'firewall_vip64_dynamicmapping'
                    - 'firewall_vip64_realservers'
                    - 'firewall_vip6_dynamicmapping'
                    - 'firewall_vip6_dynamicmapping_realservers'
                    - 'firewall_vip6_dynamicmapping_sslciphersuites'
                    - 'firewall_vip6_realservers'
                    - 'firewall_vip6_sslciphersuites'
                    - 'firewall_vip6_sslserverciphersuites'
                    - 'firewall_vip_dynamicmapping'
                    - 'firewall_vip_dynamicmapping_realservers'
                    - 'firewall_vip_dynamicmapping_sslciphersuites'
                    - 'firewall_vip_realservers'
                    - 'firewall_vip_sslciphersuites'
                    - 'firewall_vip_sslserverciphersuites'
                    - 'firewall_vipgrp'
                    - 'firewall_vipgrp46'
                    - 'firewall_vipgrp6'
                    - 'firewall_vipgrp64'
                    - 'firewall_vipgrp_dynamicmapping'
                    - 'firewall_wildcardfqdn_custom'
                    - 'firewall_wildcardfqdn_group'
                    - 'fmg_device_blueprint'
                    - 'fmg_fabric_authorization_template'
                    - 'fmg_fabric_authorization_template_platforms'
                    - 'fmg_variable'
                    - 'fmg_variable_dynamicmapping'
                    - 'fsp_vlan'
                    - 'fsp_vlan_dhcpserver_excluderange'
                    - 'fsp_vlan_dhcpserver_iprange'
                    - 'fsp_vlan_dhcpserver_options'
                    - 'fsp_vlan_dhcpserver_reservedaddress'
                    - 'fsp_vlan_dynamicmapping'
                    - 'fsp_vlan_dynamicmapping_dhcpserver_excluderange'
                    - 'fsp_vlan_dynamicmapping_dhcpserver_iprange'
                    - 'fsp_vlan_dynamicmapping_dhcpserver_options'
                    - 'fsp_vlan_dynamicmapping_dhcpserver_reservedaddress'
                    - 'fsp_vlan_dynamicmapping_interface_ipv6_ip6delegatedprefixlist'
                    - 'fsp_vlan_dynamicmapping_interface_ipv6_ip6extraaddr'
                    - 'fsp_vlan_dynamicmapping_interface_ipv6_ip6prefixlist'
                    - 'fsp_vlan_dynamicmapping_interface_ipv6_vrrp6'
                    - 'fsp_vlan_dynamicmapping_interface_secondaryip'
                    - 'fsp_vlan_dynamicmapping_interface_vrrp'
                    - 'fsp_vlan_dynamicmapping_interface_vrrp_proxyarp'
                    - 'fsp_vlan_interface_ipv6_ip6delegatedprefixlist'
                    - 'fsp_vlan_interface_ipv6_ip6extraaddr'
                    - 'fsp_vlan_interface_ipv6_ip6prefixlist'
                    - 'fsp_vlan_interface_ipv6_vrrp6'
                    - 'fsp_vlan_interface_secondaryip'
                    - 'fsp_vlan_interface_vrrp'
                    - 'fsp_vlan_interface_vrrp_proxyarp'
                    - 'gtp_apn'
                    - 'gtp_apngrp'
                    - 'gtp_iewhitelist'
                    - 'gtp_iewhitelist_entries'
                    - 'gtp_messagefilterv0v1'
                    - 'gtp_messagefilterv2'
                    - 'gtp_tunnellimit'
                    - 'hotspot20_anqp3gppcellular'
                    - 'hotspot20_anqp3gppcellular_mccmnclist'
                    - 'hotspot20_anqpipaddresstype'
                    - 'hotspot20_anqpnairealm'
                    - 'hotspot20_anqpnairealm_nailist'
                    - 'hotspot20_anqpnairealm_nailist_eapmethod'
                    - 'hotspot20_anqpnairealm_nailist_eapmethod_authparam'
                    - 'hotspot20_anqpnetworkauthtype'
                    - 'hotspot20_anqproamingconsortium'
                    - 'hotspot20_anqproamingconsortium_oilist'
                    - 'hotspot20_anqpvenuename'
                    - 'hotspot20_anqpvenuename_valuelist'
                    - 'hotspot20_anqpvenueurl'
                    - 'hotspot20_anqpvenueurl_valuelist'
                    - 'hotspot20_h2qpadviceofcharge'
                    - 'hotspot20_h2qpadviceofcharge_aoclist'
                    - 'hotspot20_h2qpadviceofcharge_aoclist_planinfo'
                    - 'hotspot20_h2qpconncapability'
                    - 'hotspot20_h2qpoperatorname'
                    - 'hotspot20_h2qpoperatorname_valuelist'
                    - 'hotspot20_h2qposuprovider'
                    - 'hotspot20_h2qposuprovider_friendlyname'
                    - 'hotspot20_h2qposuprovider_servicedescription'
                    - 'hotspot20_h2qposuprovidernai'
                    - 'hotspot20_h2qposuprovidernai_nailist'
                    - 'hotspot20_h2qptermsandconditions'
                    - 'hotspot20_h2qpwanmetric'
                    - 'hotspot20_hsprofile'
                    - 'hotspot20_icon'
                    - 'hotspot20_icon_iconlist'
                    - 'hotspot20_qosmap'
                    - 'hotspot20_qosmap_dscpexcept'
                    - 'hotspot20_qosmap_dscprange'
                    - 'icap_profile'
                    - 'icap_profile_icapheaders'
                    - 'icap_profile_respmodforwardrules'
                    - 'icap_profile_respmodforwardrules_headergroup'
                    - 'icap_server'
                    - 'ips_baseline_sensor'
                    - 'ips_baseline_sensor_entries'
                    - 'ips_baseline_sensor_entries_exemptip'
                    - 'ips_baseline_sensor_filter'
                    - 'ips_baseline_sensor_override'
                    - 'ips_baseline_sensor_override_exemptip'
                    - 'ips_custom'
                    - 'ips_sensor'
                    - 'ips_sensor_entries'
                    - 'ips_sensor_entries_exemptip'
                    - 'ips_sensor_filter'
                    - 'ips_sensor_override'
                    - 'ips_sensor_override_exemptip'
                    - 'log_customfield'
                    - 'log_npuserver_servergroup'
                    - 'log_npuserver_serverinfo'
                    - 'mpskprofile'
                    - 'mpskprofile_mpskgroup'
                    - 'mpskprofile_mpskgroup_mpskkey'
                    - 'nacprofile'
                    - 'pkg_authentication_rule'
                    - 'pkg_central_dnat'
                    - 'pkg_central_dnat6'
                    - 'pkg_firewall_acl'
                    - 'pkg_firewall_acl6'
                    - 'pkg_firewall_centralsnatmap'
                    - 'pkg_firewall_consolidated_policy'
                    - 'pkg_firewall_dospolicy'
                    - 'pkg_firewall_dospolicy6'
                    - 'pkg_firewall_dospolicy6_anomaly'
                    - 'pkg_firewall_dospolicy_anomaly'
                    - 'pkg_firewall_explicitproxypolicy'
                    - 'pkg_firewall_explicitproxypolicy_identitybasedpolicy'
                    - 'pkg_firewall_hyperscalepolicy'
                    - 'pkg_firewall_hyperscalepolicy46'
                    - 'pkg_firewall_hyperscalepolicy6'
                    - 'pkg_firewall_hyperscalepolicy64'
                    - 'pkg_firewall_interfacepolicy'
                    - 'pkg_firewall_interfacepolicy6'
                    - 'pkg_firewall_localinpolicy'
                    - 'pkg_firewall_localinpolicy6'
                    - 'pkg_firewall_multicastpolicy'
                    - 'pkg_firewall_multicastpolicy6'
                    - 'pkg_firewall_policy'
                    - 'pkg_firewall_policy46'
                    - 'pkg_firewall_policy6'
                    - 'pkg_firewall_policy64'
                    - 'pkg_firewall_policy_vpndstnode'
                    - 'pkg_firewall_policy_vpnsrcnode'
                    - 'pkg_firewall_proxypolicy'
                    - 'pkg_firewall_securitypolicy'
                    - 'pkg_firewall_shapingpolicy'
                    - 'pkg_footer_consolidated_policy'
                    - 'pkg_footer_policy'
                    - 'pkg_footer_policy6'
                    - 'pkg_footer_policy6_identitybasedpolicy6'
                    - 'pkg_footer_policy_identitybasedpolicy'
                    - 'pkg_footer_shapingpolicy'
                    - 'pkg_header_consolidated_policy'
                    - 'pkg_header_policy'
                    - 'pkg_header_policy6'
                    - 'pkg_header_policy6_identitybasedpolicy6'
                    - 'pkg_header_policy_identitybasedpolicy'
                    - 'pkg_header_shapingpolicy'
                    - 'pkg_user_nacpolicy'
                    - 'pm_config_pblock_firewall_consolidated_policy'
                    - 'pm_config_pblock_firewall_policy'
                    - 'pm_config_pblock_firewall_policy6'
                    - 'pm_config_pblock_firewall_securitypolicy'
                    - 'qosprofile'
                    - 'region'
                    - 'router_accesslist'
                    - 'router_accesslist6'
                    - 'router_accesslist6_rule'
                    - 'router_accesslist_rule'
                    - 'router_aspathlist'
                    - 'router_aspathlist_rule'
                    - 'router_communitylist'
                    - 'router_communitylist_rule'
                    - 'router_prefixlist'
                    - 'router_prefixlist6'
                    - 'router_prefixlist6_rule'
                    - 'router_prefixlist_rule'
                    - 'router_routemap'
                    - 'router_routemap_rule'
                    - 'spamfilter_bwl'
                    - 'spamfilter_bwl_entries'
                    - 'spamfilter_bword'
                    - 'spamfilter_bword_entries'
                    - 'spamfilter_dnsbl'
                    - 'spamfilter_dnsbl_entries'
                    - 'spamfilter_iptrust'
                    - 'spamfilter_iptrust_entries'
                    - 'spamfilter_mheader'
                    - 'spamfilter_mheader_entries'
                    - 'spamfilter_profile'
                    - 'sshfilter_profile'
                    - 'sshfilter_profile_filefilter_entries'
                    - 'sshfilter_profile_shellcommands'
                    - 'switchcontroller_acl_group'
                    - 'switchcontroller_acl_ingress'
                    - 'switchcontroller_customcommand'
                    - 'switchcontroller_dsl_policy'
                    - 'switchcontroller_dynamicportpolicy'
                    - 'switchcontroller_dynamicportpolicy_policy'
                    - 'switchcontroller_fortilinksettings'
                    - 'switchcontroller_lldpprofile'
                    - 'switchcontroller_lldpprofile_customtlvs'
                    - 'switchcontroller_lldpprofile_medlocationservice'
                    - 'switchcontroller_lldpprofile_mednetworkpolicy'
                    - 'switchcontroller_macpolicy'
                    - 'switchcontroller_managedswitch'
                    - 'switchcontroller_managedswitch_customcommand'
                    - 'switchcontroller_managedswitch_dhcpsnoopingstaticclient'
                    - 'switchcontroller_managedswitch_ipsourceguard'
                    - 'switchcontroller_managedswitch_ipsourceguard_bindingentry'
                    - 'switchcontroller_managedswitch_mirror'
                    - 'switchcontroller_managedswitch_ports'
                    - 'switchcontroller_managedswitch_ports_dhcpsnoopoption82override'
                    - 'switchcontroller_managedswitch_remotelog'
                    - 'switchcontroller_managedswitch_snmpcommunity'
                    - 'switchcontroller_managedswitch_snmpcommunity_hosts'
                    - 'switchcontroller_managedswitch_snmpuser'
                    - 'switchcontroller_managedswitch_staticmac'
                    - 'switchcontroller_managedswitch_stpinstance'
                    - 'switchcontroller_qos_dot1pmap'
                    - 'switchcontroller_qos_ipdscpmap'
                    - 'switchcontroller_qos_ipdscpmap_map'
                    - 'switchcontroller_qos_qospolicy'
                    - 'switchcontroller_qos_queuepolicy'
                    - 'switchcontroller_qos_queuepolicy_cosqueue'
                    - 'switchcontroller_securitypolicy_8021x'
                    - 'switchcontroller_securitypolicy_captiveportal'
                    - 'switchcontroller_switchinterfacetag'
                    - 'switchcontroller_trafficpolicy'
                    - 'switchcontroller_vlanpolicy'
                    - 'system_customlanguage'
                    - 'system_dhcp_server'
                    - 'system_dhcp_server_excluderange'
                    - 'system_dhcp_server_iprange'
                    - 'system_dhcp_server_options'
                    - 'system_dhcp_server_reservedaddress'
                    - 'system_externalresource'
                    - 'system_geoipcountry'
                    - 'system_geoipoverride'
                    - 'system_geoipoverride_ip6range'
                    - 'system_geoipoverride_iprange'
                    - 'system_meta'
                    - 'system_meta_sysmetafields'
                    - 'system_npu_dswdtsprofile'
                    - 'system_npu_dswqueuedtsprofile'
                    - 'system_npu_npqueues_ethernettype'
                    - 'system_npu_npqueues_ipprotocol'
                    - 'system_npu_npqueues_ipservice'
                    - 'system_npu_npqueues_profile'
                    - 'system_npu_npqueues_scheduler'
                    - 'system_npu_portcpumap'
                    - 'system_npu_portnpumap'
                    - 'system_npu_tcptimeoutprofile'
                    - 'system_npu_udptimeoutprofile'
                    - 'system_objecttag'
                    - 'system_objecttagging'
                    - 'system_replacemsggroup'
                    - 'system_replacemsggroup_admin'
                    - 'system_replacemsggroup_alertmail'
                    - 'system_replacemsggroup_auth'
                    - 'system_replacemsggroup_automation'
                    - 'system_replacemsggroup_custommessage'
                    - 'system_replacemsggroup_devicedetectionportal'
                    - 'system_replacemsggroup_ec'
                    - 'system_replacemsggroup_fortiguardwf'
                    - 'system_replacemsggroup_ftp'
                    - 'system_replacemsggroup_http'
                    - 'system_replacemsggroup_icap'
                    - 'system_replacemsggroup_mail'
                    - 'system_replacemsggroup_mm1'
                    - 'system_replacemsggroup_mm3'
                    - 'system_replacemsggroup_mm4'
                    - 'system_replacemsggroup_mm7'
                    - 'system_replacemsggroup_mms'
                    - 'system_replacemsggroup_nacquar'
                    - 'system_replacemsggroup_nntp'
                    - 'system_replacemsggroup_spam'
                    - 'system_replacemsggroup_sslvpn'
                    - 'system_replacemsggroup_trafficquota'
                    - 'system_replacemsggroup_utm'
                    - 'system_replacemsggroup_webproxy'
                    - 'system_replacemsgimage'
                    - 'system_sdnconnector'
                    - 'system_sdnconnector_compartmentlist'
                    - 'system_sdnconnector_externalaccountlist'
                    - 'system_sdnconnector_externalip'
                    - 'system_sdnconnector_forwardingrule'
                    - 'system_sdnconnector_gcpprojectlist'
                    - 'system_sdnconnector_nic'
                    - 'system_sdnconnector_nic_ip'
                    - 'system_sdnconnector_ociregionlist'
                    - 'system_sdnconnector_route'
                    - 'system_sdnconnector_routetable'
                    - 'system_sdnconnector_routetable_route'
                    - 'system_smsserver'
                    - 'system_virtualwirepair'
                    - 'template'
                    - 'templategroup'
                    - 'user_adgrp'
                    - 'user_certificate'
                    - 'user_clearpass'
                    - 'user_connector'
                    - 'user_device'
                    - 'user_device_dynamicmapping'
                    - 'user_device_tagging'
                    - 'user_deviceaccesslist'
                    - 'user_deviceaccesslist_devicelist'
                    - 'user_devicecategory'
                    - 'user_devicegroup'
                    - 'user_devicegroup_dynamicmapping'
                    - 'user_devicegroup_tagging'
                    - 'user_domaincontroller'
                    - 'user_domaincontroller_extraserver'
                    - 'user_exchange'
                    - 'user_flexvm'
                    - 'user_fortitoken'
                    - 'user_fsso'
                    - 'user_fsso_dynamicmapping'
                    - 'user_fssopolling'
                    - 'user_fssopolling_adgrp'
                    - 'user_group'
                    - 'user_group_dynamicmapping'
                    - 'user_group_dynamicmapping_guest'
                    - 'user_group_dynamicmapping_match'
                    - 'user_group_guest'
                    - 'user_group_match'
                    - 'user_json'
                    - 'user_krbkeytab'
                    - 'user_ldap'
                    - 'user_ldap_dynamicmapping'
                    - 'user_local'
                    - 'user_nsx'
                    - 'user_nsx_service'
                    - 'user_passwordpolicy'
                    - 'user_peer'
                    - 'user_peergrp'
                    - 'user_pop3'
                    - 'user_pxgrid'
                    - 'user_radius'
                    - 'user_radius_accountingserver'
                    - 'user_radius_dynamicmapping'
                    - 'user_radius_dynamicmapping_accountingserver'
                    - 'user_saml'
                    - 'user_saml_dynamicmapping'
                    - 'user_securityexemptlist'
                    - 'user_securityexemptlist_rule'
                    - 'user_tacacs'
                    - 'user_tacacs_dynamicmapping'
                    - 'user_vcenter'
                    - 'user_vcenter_rule'
                    - 'utmprofile'
                    - 'vap'
                    - 'vap_dynamicmapping'
                    - 'vap_macfilterlist'
                    - 'vap_mpskkey'
                    - 'vap_vlanname'
                    - 'vap_vlanpool'
                    - 'vapgroup'
                    - 'videofilter_profile'
                    - 'videofilter_profile_fortiguardcategory_filters'
                    - 'videofilter_youtubechannelfilter'
                    - 'videofilter_youtubechannelfilter_entries'
                    - 'voip_profile'
                    - 'vpn_certificate_ca'
                    - 'vpn_certificate_ocspserver'
                    - 'vpn_certificate_remote'
                    - 'vpn_ipsec_fec'
                    - 'vpn_ipsec_fec_mappings'
                    - 'vpn_ssl_settings_authenticationrule'
                    - 'vpnmgr_node'
                    - 'vpnmgr_node_iprange'
                    - 'vpnmgr_node_ipv4excluderange'
                    - 'vpnmgr_node_protectedsubnet'
                    - 'vpnmgr_node_summaryaddr'
                    - 'vpnmgr_vpntable'
                    - 'vpnsslweb_hostchecksoftware'
                    - 'vpnsslweb_hostchecksoftware_checkitemlist'
                    - 'vpnsslweb_portal'
                    - 'vpnsslweb_portal_bookmarkgroup'
                    - 'vpnsslweb_portal_bookmarkgroup_bookmarks'
                    - 'vpnsslweb_portal_bookmarkgroup_bookmarks_formdata'
                    - 'vpnsslweb_portal_landingpage_formdata'
                    - 'vpnsslweb_portal_macaddrcheckrule'
                    - 'vpnsslweb_portal_splitdns'
                    - 'vpnsslweb_realm'
                    - 'vpnsslweb_virtualdesktopapplist'
                    - 'vpnsslweb_virtualdesktopapplist_apps'
                    - 'waf_mainclass'
                    - 'waf_profile'
                    - 'waf_profile_constraint_exception'
                    - 'waf_profile_method_methodpolicy'
                    - 'waf_profile_signature_customsignature'
                    - 'waf_profile_urlaccess'
                    - 'waf_profile_urlaccess_accesspattern'
                    - 'waf_signature'
                    - 'waf_subclass'
                    - 'wagprofile'
                    - 'wanopt_authgroup'
                    - 'wanopt_peer'
                    - 'wanopt_profile'
                    - 'wanprof_system_sdwan_duplication'
                    - 'wanprof_system_sdwan_healthcheck'
                    - 'wanprof_system_sdwan_healthcheck_sla'
                    - 'wanprof_system_sdwan_members'
                    - 'wanprof_system_sdwan_neighbor'
                    - 'wanprof_system_sdwan_service'
                    - 'wanprof_system_sdwan_service_sla'
                    - 'wanprof_system_sdwan_zone'
                    - 'wanprof_system_virtualwanlink_healthcheck'
                    - 'wanprof_system_virtualwanlink_healthcheck_sla'
                    - 'wanprof_system_virtualwanlink_members'
                    - 'wanprof_system_virtualwanlink_neighbor'
                    - 'wanprof_system_virtualwanlink_service'
                    - 'wanprof_system_virtualwanlink_service_sla'
                    - 'webfilter_categories'
                    - 'webfilter_content'
                    - 'webfilter_content_entries'
                    - 'webfilter_contentheader'
                    - 'webfilter_contentheader_entries'
                    - 'webfilter_ftgdlocalcat'
                    - 'webfilter_ftgdlocalrating'
                    - 'webfilter_profile'
                    - 'webfilter_profile_antiphish_custompatterns'
                    - 'webfilter_profile_antiphish_inspectionentries'
                    - 'webfilter_profile_filefilter_entries'
                    - 'webfilter_profile_ftgdwf_filters'
                    - 'webfilter_profile_ftgdwf_quota'
                    - 'webfilter_profile_youtubechannelfilter'
                    - 'webfilter_urlfilter'
                    - 'webfilter_urlfilter_entries'
                    - 'webproxy_forwardserver'
                    - 'webproxy_forwardservergroup'
                    - 'webproxy_forwardservergroup_serverlist'
                    - 'webproxy_profile'
                    - 'webproxy_profile_headers'
                    - 'webproxy_wisp'
                    - 'widsprofile'
                    - 'wireless_accesscontrollist'
                    - 'wireless_accesscontrollist_layer3ipv4rules'
                    - 'wireless_accesscontrollist_layer3ipv6rules'
                    - 'wireless_address'
                    - 'wireless_addrgrp'
                    - 'wireless_ssidpolicy'
                    - 'wireless_syslogprofile'
                    - 'wtpprofile'
                    - 'wtpprofile_denymaclist'
                    - 'wtpprofile_splittunnelingacl'
            self:
                required: true
                description: The parameter for each selector.
                type: dict
            target:
                required: true
                description: Attribute to override for target object.
                type: dict
'''

EXAMPLES = '''
- hosts: fortimanager01
  collections:
    - fortinet.fortimanager
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: True
    ansible_httpapi_validate_certs: False
    ansible_httpapi_port: 443
  tasks:
    - name: clone an vip object using fmgr_clone module.
      fmgr_clone:
        clone:
          selector: "firewall_vip"
          self:
            adom: "root"
            vip: "ansible-test-vip_first"
          target:
            name: "ansible-test-vip_fourth"
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


def main():
    clone_metadata = {
        'antivirus_mmschecksum': {
            'params': [
                'adom',
                'mms-checksum'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/mms-checksum/{mms-checksum}',
                '/pm/config/global/obj/antivirus/mms-checksum/{mms-checksum}'
            ],
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
            'mkey': 'id'
        },
        'antivirus_mmschecksum_entries': {
            'params': [
                'adom',
                'mms-checksum',
                'entries'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/mms-checksum/{mms-checksum}/entries/{entries}',
                '/pm/config/global/obj/antivirus/mms-checksum/{mms-checksum}/entries/{entries}'
            ],
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
            'mkey': 'name'
        },
        'antivirus_notification': {
            'params': [
                'adom',
                'notification'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/notification/{notification}',
                '/pm/config/global/obj/antivirus/notification/{notification}'
            ],
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
            'mkey': 'id'
        },
        'antivirus_notification_entries': {
            'params': [
                'adom',
                'notification',
                'entries'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/notification/{notification}/entries/{entries}',
                '/pm/config/global/obj/antivirus/notification/{notification}/entries/{entries}'
            ],
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
            'mkey': 'name'
        },
        'antivirus_profile': {
            'params': [
                'adom',
                'profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}',
                '/pm/config/global/obj/antivirus/profile/{profile}'
            ],
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
            'mkey': 'name'
        },
        'apcfgprofile': {
            'params': [
                'apcfg-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/apcfg-profile/{apcfg-profile}',
                '/pm/config/adom/{adom}/obj/wireless-controller/apcfg-profile/{apcfg-profile}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'apcfgprofile_commandlist': {
            'params': [
                'apcfg-profile',
                'command-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/apcfg-profile/{apcfg-profile}/command-list/{command-list}',
                '/pm/config/adom/{adom}/obj/wireless-controller/apcfg-profile/{apcfg-profile}/command-list/{command-list}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'application_casi_profile': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/application/casi/profile/{profile}',
                '/pm/config/adom/{adom}/obj/application/casi/profile/{profile}'
            ],
            'revision': {
                '6.2.0': True,
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.6': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True
            },
            'mkey': 'name'
        },
        'application_casi_profile_entries': {
            'params': [
                'profile',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/application/casi/profile/{profile}/entries/{entries}',
                '/pm/config/adom/{adom}/obj/application/casi/profile/{profile}/entries/{entries}'
            ],
            'revision': {
                '6.2.0': True,
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.6': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True
            },
            'mkey': 'id'
        },
        'application_categories': {
            'params': [
                'adom',
                'categories'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/categories/{categories}',
                '/pm/config/global/obj/application/categories/{categories}'
            ],
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
            'mkey': 'id'
        },
        'application_custom': {
            'params': [
                'adom',
                'custom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/custom/{custom}',
                '/pm/config/global/obj/application/custom/{custom}'
            ],
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
            'mkey': 'tag'
        },
        'application_group': {
            'params': [
                'adom',
                'group'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/group/{group}',
                '/pm/config/global/obj/application/group/{group}'
            ],
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
            'mkey': 'name'
        },
        'application_internetservice_entry': {
            'params': [
                'entry',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/application/internet-service/entry/{entry}',
                '/pm/config/adom/{adom}/obj/application/internet-service/entry/{entry}'
            ],
            'revision': {
                '6.2.0': True,
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.6': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True
            },
            'mkey': 'id'
        },
        'application_internetservicecustom': {
            'params': [
                'internet-service-custom',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/application/internet-service-custom/{internet-service-custom}',
                '/pm/config/adom/{adom}/obj/application/internet-service-custom/{internet-service-custom}'
            ],
            'revision': {
                '6.2.0': True,
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.6': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True
            },
            'mkey': 'name'
        },
        'application_internetservicecustom_disableentry': {
            'params': [
                'internet-service-custom',
                'disable-entry',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/application/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}',
                '/pm/config/adom/{adom}/obj/application/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}'
            ],
            'revision': {
                '6.2.0': True,
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.6': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True
            },
            'mkey': 'id'
        },
        'application_internetservicecustom_disableentry_iprange': {
            'params': [
                'internet-service-custom',
                'disable-entry',
                'ip-range',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/application/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}/ip-range/{ip-range}',
                '/pm/config/adom/{adom}/obj/application/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}/ip-range/{ip-range}'
            ],
            'revision': {
                '6.2.0': True,
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.6': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True
            },
            'mkey': 'id'
        },
        'application_internetservicecustom_entry': {
            'params': [
                'internet-service-custom',
                'entry',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/application/internet-service-custom/{internet-service-custom}/entry/{entry}',
                '/pm/config/adom/{adom}/obj/application/internet-service-custom/{internet-service-custom}/entry/{entry}'
            ],
            'revision': {
                '6.2.0': True,
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.6': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True
            },
            'mkey': 'id'
        },
        'application_internetservicecustom_entry_portrange': {
            'params': [
                'internet-service-custom',
                'entry',
                'port-range',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/application/internet-service-custom/{internet-service-custom}/entry/{entry}/port-range/{port-range}',
                '/pm/config/adom/{adom}/obj/application/internet-service-custom/{internet-service-custom}/entry/{entry}/port-range/{port-range}'
            ],
            'revision': {
                '6.2.0': True,
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.6': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True
            },
            'mkey': 'id'
        },
        'application_list': {
            'params': [
                'adom',
                'list'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/list/{list}',
                '/pm/config/global/obj/application/list/{list}'
            ],
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
            'mkey': 'name'
        },
        'application_list_defaultnetworkservices': {
            'params': [
                'list',
                'default-network-services',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/application/list/{list}/default-network-services/{default-network-services}',
                '/pm/config/adom/{adom}/obj/application/list/{list}/default-network-services/{default-network-services}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'application_list_entries': {
            'params': [
                'adom',
                'list',
                'entries'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/list/{list}/entries/{entries}',
                '/pm/config/global/obj/application/list/{list}/entries/{entries}'
            ],
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
            'mkey': 'id'
        },
        'application_list_entries_parameters': {
            'params': [
                'adom',
                'list',
                'entries',
                'parameters'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/list/{list}/entries/{entries}/parameters/{parameters}',
                '/pm/config/global/obj/application/list/{list}/entries/{entries}/parameters/{parameters}'
            ],
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
            'mkey': 'id'
        },
        'application_list_entries_parameters_members': {
            'params': [
                'list',
                'entries',
                'parameters',
                'members',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/application/list/{list}/entries/{entries}/parameters/{parameters}/members/{members}',
                '/pm/config/adom/{adom}/obj/application/list/{list}/entries/{entries}/parameters/{parameters}/members/{members}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'arrpprofile': {
            'params': [
                'arrp-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/arrp-profile/{arrp-profile}',
                '/pm/config/adom/{adom}/obj/wireless-controller/arrp-profile/{arrp-profile}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'authentication_scheme': {
            'params': [
                'scheme',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/authentication/scheme/{scheme}',
                '/pm/config/adom/{adom}/obj/authentication/scheme/{scheme}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'bleprofile': {
            'params': [
                'adom',
                'ble-profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/ble-profile/{ble-profile}',
                '/pm/config/global/obj/wireless-controller/ble-profile/{ble-profile}'
            ],
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
            'mkey': 'name'
        },
        'bonjourprofile': {
            'params': [
                'adom',
                'bonjour-profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/bonjour-profile/{bonjour-profile}',
                '/pm/config/global/obj/wireless-controller/bonjour-profile/{bonjour-profile}'
            ],
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
            'mkey': 'name'
        },
        'bonjourprofile_policylist': {
            'params': [
                'adom',
                'bonjour-profile',
                'policy-list'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/bonjour-profile/{bonjour-profile}/policy-list/{policy-list}',
                '/pm/config/global/obj/wireless-controller/bonjour-profile/{bonjour-profile}/policy-list/{policy-list}'
            ],
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
            'mkey': 'policy-id'
        },
        'certificate_template': {
            'params': [
                'adom',
                'template'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/certificate/template/{template}',
                '/pm/config/global/obj/certificate/template/{template}'
            ],
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
            'mkey': 'name'
        },
        'cifs_domaincontroller': {
            'params': [
                'domain-controller',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/cifs/domain-controller/{domain-controller}',
                '/pm/config/adom/{adom}/obj/cifs/domain-controller/{domain-controller}'
            ],
            'revision': {
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
            'mkey': None
        },
        'cifs_profile': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/cifs/profile/{profile}',
                '/pm/config/adom/{adom}/obj/cifs/profile/{profile}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'cifs_profile_filefilter_entries': {
            'params': [
                'profile',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/cifs/profile/{profile}/file-filter/entries/{entries}',
                '/pm/config/adom/{adom}/obj/cifs/profile/{profile}/file-filter/entries/{entries}'
            ],
            'revision': {
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
            'mkey': None
        },
        'cifs_profile_serverkeytab': {
            'params': [
                'profile',
                'server-keytab',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/cifs/profile/{profile}/server-keytab/{server-keytab}',
                '/pm/config/adom/{adom}/obj/cifs/profile/{profile}/server-keytab/{server-keytab}'
            ],
            'revision': {
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
            'mkey': None
        },
        'cloud_orchestaws': {
            'params': [
                'orchest-aws',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/cloud/orchest-aws/{orchest-aws}',
                '/pm/config/adom/{adom}/obj/cloud/orchest-aws/{orchest-aws}'
            ],
            'revision': {
                '7.4.0': True
            },
            'mkey': 'name'
        },
        'cloud_orchestawsconnector': {
            'params': [
                'orchest-awsconnector',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/cloud/orchest-awsconnector/{orchest-awsconnector}',
                '/pm/config/adom/{adom}/obj/cloud/orchest-awsconnector/{orchest-awsconnector}'
            ],
            'revision': {
                '7.4.0': True
            },
            'mkey': 'name'
        },
        'cloud_orchestawstemplate_autoscaleexistingvpc': {
            'params': [
                'autoscale-existing-vpc',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/cloud/orchest-awstemplate/autoscale-existing-vpc/{autoscale-existing-vpc}',
                '/pm/config/adom/{adom}/obj/cloud/orchest-awstemplate/autoscale-existing-vpc/{autoscale-existing-vpc}'
            ],
            'revision': {
                '7.4.0': True
            },
            'mkey': 'name'
        },
        'cloud_orchestawstemplate_autoscalenewvpc': {
            'params': [
                'autoscale-new-vpc',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/cloud/orchest-awstemplate/autoscale-new-vpc/{autoscale-new-vpc}',
                '/pm/config/adom/{adom}/obj/cloud/orchest-awstemplate/autoscale-new-vpc/{autoscale-new-vpc}'
            ],
            'revision': {
                '7.4.0': True
            },
            'mkey': 'name'
        },
        'cloud_orchestawstemplate_autoscaletgwnewvpc': {
            'params': [
                'autoscale-tgw-new-vpc',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/cloud/orchest-awstemplate/autoscale-tgw-new-vpc/{autoscale-tgw-new-vpc}',
                '/pm/config/adom/{adom}/obj/cloud/orchest-awstemplate/autoscale-tgw-new-vpc/{autoscale-tgw-new-vpc}'
            ],
            'revision': {
                '7.4.0': True
            },
            'mkey': 'name'
        },
        'cloud_orchestration': {
            'params': [
                'orchestration',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/cloud/orchestration/{orchestration}',
                '/pm/config/adom/{adom}/obj/cloud/orchestration/{orchestration}'
            ],
            'revision': {
                '7.4.0': True
            },
            'mkey': 'name'
        },
        'credentialstore_domaincontroller': {
            'params': [
                'domain-controller',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/credential-store/domain-controller/{domain-controller}',
                '/pm/config/adom/{adom}/obj/credential-store/domain-controller/{domain-controller}'
            ],
            'revision': {
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
            'mkey': None
        },
        'devprof_log_syslogd_filter_excludelist': {
            'params': [
                'adom',
                'devprof',
                'exclude-list'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/log/syslogd/filter/exclude-list/{exclude-list}'
            ],
            'revision': {
                '7.0.4': True,
                '7.0.5': True,
                '7.0.6': True,
                '7.0.7': True
            },
            'mkey': 'id'
        },
        'devprof_log_syslogd_filter_excludelist_fields': {
            'params': [
                'adom',
                'devprof',
                'exclude-list',
                'fields'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/log/syslogd/filter/exclude-list/{exclude-list}/fields/{fields}'
            ],
            'revision': {
                '7.0.4': True,
                '7.0.5': True,
                '7.0.6': True,
                '7.0.7': True
            },
            'mkey': None
        },
        'devprof_log_syslogd_filter_freestyle': {
            'params': [
                'adom',
                'devprof',
                'free-style'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/log/syslogd/filter/free-style/{free-style}'
            ],
            'revision': {
                '7.0.4': True,
                '7.0.5': True,
                '7.0.6': True,
                '7.0.7': True,
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'id'
        },
        'devprof_log_syslogd_setting_customfieldname': {
            'params': [
                'adom',
                'devprof',
                'custom-field-name'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/log/syslogd/setting/custom-field-name/{custom-field-name}'
            ],
            'revision': {
                '7.0.4': True,
                '7.0.5': True,
                '7.0.6': True,
                '7.0.7': True,
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'id'
        },
        'devprof_system_centralmanagement_serverlist': {
            'params': [
                'adom',
                'devprof',
                'server-list'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/central-management/server-list/{server-list}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.0': True,
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True,
                '6.4.0': True,
                '6.4.1': True,
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
            'mkey': 'id'
        },
        'devprof_system_ntp_ntpserver': {
            'params': [
                'adom',
                'devprof',
                'ntpserver'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/ntp/ntpserver/{ntpserver}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.0': True,
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True,
                '6.4.0': True,
                '6.4.1': True,
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
            'mkey': 'id'
        },
        'devprof_system_snmp_community': {
            'params': [
                'adom',
                'devprof',
                'community'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/community/{community}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.0': True,
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True,
                '6.4.0': True,
                '6.4.1': True,
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
            'mkey': 'id'
        },
        'devprof_system_snmp_community_hosts': {
            'params': [
                'adom',
                'devprof',
                'community',
                'hosts'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/community/{community}/hosts/{hosts}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.0': True,
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True,
                '6.4.0': True,
                '6.4.1': True,
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
            'mkey': 'id'
        },
        'devprof_system_snmp_community_hosts6': {
            'params': [
                'adom',
                'devprof',
                'community',
                'hosts6'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/community/{community}/hosts6/{hosts6}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.0': True,
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True,
                '6.4.0': True,
                '6.4.1': True,
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
            'mkey': 'id'
        },
        'devprof_system_snmp_user': {
            'params': [
                'adom',
                'devprof',
                'user'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/user/{user}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.0': True,
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True,
                '6.4.0': True,
                '6.4.1': True,
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
            'mkey': 'name'
        },
        'dlp_datatype': {
            'params': [
                'data-type',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/dlp/data-type/{data-type}',
                '/pm/config/adom/{adom}/obj/dlp/data-type/{data-type}'
            ],
            'revision': {
                '7.2.0': True,
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'name'
        },
        'dlp_dictionary': {
            'params': [
                'dictionary',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/dlp/dictionary/{dictionary}',
                '/pm/config/adom/{adom}/obj/dlp/dictionary/{dictionary}'
            ],
            'revision': {
                '7.2.0': True,
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'name'
        },
        'dlp_dictionary_entries': {
            'params': [
                'dictionary',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/dlp/dictionary/{dictionary}/entries/{entries}',
                '/pm/config/adom/{adom}/obj/dlp/dictionary/{dictionary}/entries/{entries}'
            ],
            'revision': {
                '7.2.0': True,
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'id'
        },
        'dlp_filepattern': {
            'params': [
                'adom',
                'filepattern'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/filepattern/{filepattern}',
                '/pm/config/global/obj/dlp/filepattern/{filepattern}'
            ],
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
            'mkey': 'id'
        },
        'dlp_filepattern_entries': {
            'params': [
                'adom',
                'filepattern',
                'entries'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/filepattern/{filepattern}/entries/{entries}',
                '/pm/config/global/obj/dlp/filepattern/{filepattern}/entries/{entries}'
            ],
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
            'mkey': None
        },
        'dlp_fpsensitivity': {
            'params': [
                'adom',
                'fp-sensitivity'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/fp-sensitivity/{fp-sensitivity}',
                '/pm/config/global/obj/dlp/fp-sensitivity/{fp-sensitivity}'
            ],
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
                '7.2.1': True
            },
            'mkey': 'name'
        },
        'dlp_profile': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/dlp/profile/{profile}',
                '/pm/config/adom/{adom}/obj/dlp/profile/{profile}'
            ],
            'revision': {
                '7.2.0': True,
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'name'
        },
        'dlp_profile_rule': {
            'params': [
                'profile',
                'rule',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/dlp/profile/{profile}/rule/{rule}',
                '/pm/config/adom/{adom}/obj/dlp/profile/{profile}/rule/{rule}'
            ],
            'revision': {
                '7.2.0': True,
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'id'
        },
        'dlp_sensitivity': {
            'params': [
                'sensitivity',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/dlp/sensitivity/{sensitivity}',
                '/pm/config/adom/{adom}/obj/dlp/sensitivity/{sensitivity}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'dlp_sensor': {
            'params': [
                'adom',
                'sensor'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/sensor/{sensor}',
                '/pm/config/global/obj/dlp/sensor/{sensor}'
            ],
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
            'mkey': 'name'
        },
        'dlp_sensor_entries': {
            'params': [
                'sensor',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/dlp/sensor/{sensor}/entries/{entries}',
                '/pm/config/adom/{adom}/obj/dlp/sensor/{sensor}/entries/{entries}'
            ],
            'revision': {
                '7.2.0': True,
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'id'
        },
        'dlp_sensor_filter': {
            'params': [
                'adom',
                'sensor',
                'filter'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/sensor/{sensor}/filter/{filter}',
                '/pm/config/global/obj/dlp/sensor/{sensor}/filter/{filter}'
            ],
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
            'mkey': 'id'
        },
        'dnsfilter_domainfilter': {
            'params': [
                'adom',
                'domain-filter'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dnsfilter/domain-filter/{domain-filter}',
                '/pm/config/global/obj/dnsfilter/domain-filter/{domain-filter}'
            ],
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
            'mkey': 'id'
        },
        'dnsfilter_domainfilter_entries': {
            'params': [
                'adom',
                'domain-filter',
                'entries'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dnsfilter/domain-filter/{domain-filter}/entries/{entries}',
                '/pm/config/global/obj/dnsfilter/domain-filter/{domain-filter}/entries/{entries}'
            ],
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
            'mkey': 'id'
        },
        'dnsfilter_profile': {
            'params': [
                'adom',
                'profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dnsfilter/profile/{profile}',
                '/pm/config/global/obj/dnsfilter/profile/{profile}'
            ],
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
            'mkey': 'name'
        },
        'dnsfilter_profile_dnstranslation': {
            'params': [
                'profile',
                'dns-translation',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/dnsfilter/profile/{profile}/dns-translation/{dns-translation}',
                '/pm/config/adom/{adom}/obj/dnsfilter/profile/{profile}/dns-translation/{dns-translation}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'dnsfilter_profile_ftgddns_filters': {
            'params': [
                'adom',
                'profile',
                'filters'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dnsfilter/profile/{profile}/ftgd-dns/filters/{filters}',
                '/pm/config/global/obj/dnsfilter/profile/{profile}/ftgd-dns/filters/{filters}'
            ],
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
            'mkey': 'id'
        },
        'dnsfilter_urlfilter': {
            'params': [
                'urlfilter',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/dnsfilter/urlfilter/{urlfilter}',
                '/pm/config/adom/{adom}/obj/dnsfilter/urlfilter/{urlfilter}'
            ],
            'revision': {
                '6.2.0': True,
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.6': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True
            },
            'mkey': 'id'
        },
        'dnsfilter_urlfilter_entries': {
            'params': [
                'urlfilter',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/dnsfilter/urlfilter/{urlfilter}/entries/{entries}',
                '/pm/config/adom/{adom}/obj/dnsfilter/urlfilter/{urlfilter}/entries/{entries}'
            ],
            'revision': {
                '6.2.0': True,
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.6': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True
            },
            'mkey': 'id'
        },
        'dvmdb_revision': {
            'params': [
                'adom',
                'revision'
            ],
            'urls': [
                '/dvmdb/adom/{adom}/revision/{revision}',
                '/dvmdb/global/revision/{revision}',
                '/dvmdb/revision/{revision}'
            ],
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
            'mkey': 'name'
        },
        'dynamic_address': {
            'params': [
                'adom',
                'address'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/address/{address}',
                '/pm/config/global/obj/dynamic/address/{address}'
            ],
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
            'mkey': 'name'
        },
        'dynamic_address_dynamicaddrmapping': {
            'params': [
                'adom',
                'address',
                'dynamic_addr_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/address/{address}/dynamic_addr_mapping/{dynamic_addr_mapping}',
                '/pm/config/global/obj/dynamic/address/{address}/dynamic_addr_mapping/{dynamic_addr_mapping}'
            ],
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
            'mkey': 'id'
        },
        'dynamic_certificate_local': {
            'params': [
                'adom',
                'local'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/certificate/local/{local}',
                '/pm/config/global/obj/dynamic/certificate/local/{local}'
            ],
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
            'mkey': 'name'
        },
        'dynamic_certificate_local_dynamicmapping': {
            'params': [
                'adom',
                'local',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/certificate/local/{local}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/dynamic/certificate/local/{local}/dynamic_mapping/{dynamic_mapping}'
            ],
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
            'mkey': '_scope'
        },
        'dynamic_input_interface': {
            'params': [
                'interface',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/dynamic/input/interface/{interface}',
                '/pm/config/adom/{adom}/obj/dynamic/input/interface/{interface}'
            ],
            'revision': {
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.6': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True,
                '6.4.0': True
            },
            'mkey': 'name'
        },
        'dynamic_input_interface_dynamicmapping': {
            'params': [
                'interface',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/dynamic/input/interface/{interface}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/adom/{adom}/obj/dynamic/input/interface/{interface}/dynamic_mapping/{dynamic_mapping}'
            ],
            'revision': {
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.6': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True,
                '6.4.0': True
            },
            'mkey': None
        },
        'dynamic_interface': {
            'params': [
                'adom',
                'interface'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/interface/{interface}',
                '/pm/config/global/obj/dynamic/interface/{interface}'
            ],
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
            'mkey': 'name'
        },
        'dynamic_interface_dynamicmapping': {
            'params': [
                'adom',
                'interface',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/interface/{interface}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/dynamic/interface/{interface}/dynamic_mapping/{dynamic_mapping}'
            ],
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
            'mkey': '_scope'
        },
        'dynamic_interface_platformmapping': {
            'params': [
                'interface',
                'platform_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/dynamic/interface/{interface}/platform_mapping/{platform_mapping}',
                '/pm/config/adom/{adom}/obj/dynamic/interface/{interface}/platform_mapping/{platform_mapping}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'dynamic_ippool': {
            'params': [
                'adom',
                'ippool'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/ippool/{ippool}',
                '/pm/config/global/obj/dynamic/ippool/{ippool}'
            ],
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
            'mkey': 'name'
        },
        'dynamic_multicast_interface': {
            'params': [
                'adom',
                'interface'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/multicast/interface/{interface}',
                '/pm/config/global/obj/dynamic/multicast/interface/{interface}'
            ],
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
            'mkey': 'name'
        },
        'dynamic_multicast_interface_dynamicmapping': {
            'params': [
                'adom',
                'interface',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/multicast/interface/{interface}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/dynamic/multicast/interface/{interface}/dynamic_mapping/{dynamic_mapping}'
            ],
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
            'mkey': '_scope'
        },
        'dynamic_vip': {
            'params': [
                'adom',
                'vip'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/vip/{vip}',
                '/pm/config/global/obj/dynamic/vip/{vip}'
            ],
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
            'mkey': 'name'
        },
        'dynamic_virtualwanlink_members': {
            'params': [
                'adom',
                'members'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/members/{members}',
                '/pm/config/global/obj/dynamic/virtual-wan-link/members/{members}'
            ],
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
                '6.4.11': True
            },
            'mkey': 'name'
        },
        'dynamic_virtualwanlink_members_dynamicmapping': {
            'params': [
                'adom',
                'members',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/members/{members}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/dynamic/virtual-wan-link/members/{members}/dynamic_mapping/{dynamic_mapping}'
            ],
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
                '6.4.11': True
            },
            'mkey': '_scope'
        },
        'dynamic_virtualwanlink_neighbor': {
            'params': [
                'neighbor',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/dynamic/virtual-wan-link/neighbor/{neighbor}',
                '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/neighbor/{neighbor}'
            ],
            'revision': {
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
                '6.4.11': True
            },
            'mkey': 'name'
        },
        'dynamic_virtualwanlink_neighbor_dynamicmapping': {
            'params': [
                'neighbor',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/dynamic/virtual-wan-link/neighbor/{neighbor}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/neighbor/{neighbor}/dynamic_mapping/{dynamic_mapping}'
            ],
            'revision': {
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
                '6.4.11': True
            },
            'mkey': None
        },
        'dynamic_virtualwanlink_server': {
            'params': [
                'adom',
                'server'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/server/{server}',
                '/pm/config/global/obj/dynamic/virtual-wan-link/server/{server}'
            ],
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
                '6.4.11': True
            },
            'mkey': 'name'
        },
        'dynamic_virtualwanlink_server_dynamicmapping': {
            'params': [
                'adom',
                'server',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/server/{server}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/dynamic/virtual-wan-link/server/{server}/dynamic_mapping/{dynamic_mapping}'
            ],
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
                '6.4.11': True
            },
            'mkey': '_scope'
        },
        'dynamic_vpntunnel': {
            'params': [
                'adom',
                'vpntunnel'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/vpntunnel/{vpntunnel}',
                '/pm/config/global/obj/dynamic/vpntunnel/{vpntunnel}'
            ],
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
            'mkey': 'name'
        },
        'dynamic_vpntunnel_dynamicmapping': {
            'params': [
                'adom',
                'vpntunnel',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/vpntunnel/{vpntunnel}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/dynamic/vpntunnel/{vpntunnel}/dynamic_mapping/{dynamic_mapping}'
            ],
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
            'mkey': '_scope'
        },
        'emailfilter_blockallowlist': {
            'params': [
                'block-allow-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/block-allow-list/{block-allow-list}',
                '/pm/config/adom/{adom}/obj/emailfilter/block-allow-list/{block-allow-list}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'emailfilter_blockallowlist_entries': {
            'params': [
                'block-allow-list',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/block-allow-list/{block-allow-list}/entries/{entries}',
                '/pm/config/adom/{adom}/obj/emailfilter/block-allow-list/{block-allow-list}/entries/{entries}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'emailfilter_bwl': {
            'params': [
                'bwl',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/bwl/{bwl}',
                '/pm/config/adom/{adom}/obj/emailfilter/bwl/{bwl}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'emailfilter_bwl_entries': {
            'params': [
                'bwl',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/bwl/{bwl}/entries/{entries}',
                '/pm/config/adom/{adom}/obj/emailfilter/bwl/{bwl}/entries/{entries}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'emailfilter_bword': {
            'params': [
                'bword',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/bword/{bword}',
                '/pm/config/adom/{adom}/obj/emailfilter/bword/{bword}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'emailfilter_bword_entries': {
            'params': [
                'bword',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/bword/{bword}/entries/{entries}',
                '/pm/config/adom/{adom}/obj/emailfilter/bword/{bword}/entries/{entries}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'emailfilter_dnsbl': {
            'params': [
                'dnsbl',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/dnsbl/{dnsbl}',
                '/pm/config/adom/{adom}/obj/emailfilter/dnsbl/{dnsbl}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'emailfilter_dnsbl_entries': {
            'params': [
                'dnsbl',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/dnsbl/{dnsbl}/entries/{entries}',
                '/pm/config/adom/{adom}/obj/emailfilter/dnsbl/{dnsbl}/entries/{entries}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'emailfilter_iptrust': {
            'params': [
                'iptrust',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/iptrust/{iptrust}',
                '/pm/config/adom/{adom}/obj/emailfilter/iptrust/{iptrust}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'emailfilter_iptrust_entries': {
            'params': [
                'iptrust',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/iptrust/{iptrust}/entries/{entries}',
                '/pm/config/adom/{adom}/obj/emailfilter/iptrust/{iptrust}/entries/{entries}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'emailfilter_mheader': {
            'params': [
                'mheader',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/mheader/{mheader}',
                '/pm/config/adom/{adom}/obj/emailfilter/mheader/{mheader}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'emailfilter_mheader_entries': {
            'params': [
                'mheader',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/mheader/{mheader}/entries/{entries}',
                '/pm/config/adom/{adom}/obj/emailfilter/mheader/{mheader}/entries/{entries}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'emailfilter_profile': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/profile/{profile}',
                '/pm/config/adom/{adom}/obj/emailfilter/profile/{profile}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'emailfilter_profile_filefilter_entries': {
            'params': [
                'profile',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/profile/{profile}/file-filter/entries/{entries}',
                '/pm/config/adom/{adom}/obj/emailfilter/profile/{profile}/file-filter/entries/{entries}'
            ],
            'revision': {
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
            'mkey': None
        },
        'endpointcontrol_fctems': {
            'params': [
                'fctems',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/endpoint-control/fctems/{fctems}',
                '/pm/config/adom/{adom}/obj/endpoint-control/fctems/{fctems}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'extendercontroller_dataplan': {
            'params': [
                'dataplan',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/extender-controller/dataplan/{dataplan}',
                '/pm/config/adom/{adom}/obj/extender-controller/dataplan/{dataplan}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'extendercontroller_extenderprofile': {
            'params': [
                'extender-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}',
                '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'extendercontroller_extenderprofile_cellular_smsnotification_receiver': {
            'params': [
                'extender-profile',
                'receiver',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}/cellular/sms-notification/receiver/{receiver}',
                '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}/cellular/sms-notification/receiver/{receiver}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'extendercontroller_extenderprofile_lanextension_backhaul': {
            'params': [
                'extender-profile',
                'backhaul',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}/lan-extension/backhaul/{backhaul}',
                '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}/lan-extension/backhaul/{backhaul}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'extendercontroller_simprofile': {
            'params': [
                'sim_profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/extender-controller/sim_profile/{sim_profile}',
                '/pm/config/adom/{adom}/obj/extender-controller/sim_profile/{sim_profile}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'extendercontroller_template': {
            'params': [
                'template',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/extender-controller/template/{template}',
                '/pm/config/adom/{adom}/obj/extender-controller/template/{template}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'extensioncontroller_dataplan': {
            'params': [
                'dataplan',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/extension-controller/dataplan/{dataplan}',
                '/pm/config/adom/{adom}/obj/extension-controller/dataplan/{dataplan}'
            ],
            'revision': {
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'name'
        },
        'extensioncontroller_extenderprofile': {
            'params': [
                'extender-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}',
                '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}'
            ],
            'revision': {
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'id'
        },
        'extensioncontroller_extenderprofile_cellular_smsnotification_receiver': {
            'params': [
                'extender-profile',
                'receiver',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/cellular/sms-notification/receiver/{receiver}',
                '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/cellular/sms-notification/receiver/{receiver}'
            ],
            'revision': {
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'name'
        },
        'extensioncontroller_extenderprofile_lanextension_backhaul': {
            'params': [
                'extender-profile',
                'backhaul',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/lan-extension/backhaul/{backhaul}',
                '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/lan-extension/backhaul/{backhaul}'
            ],
            'revision': {
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'name'
        },
        'filefilter_profile': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/file-filter/profile/{profile}',
                '/pm/config/adom/{adom}/obj/file-filter/profile/{profile}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'filefilter_profile_rules': {
            'params': [
                'profile',
                'rules',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/file-filter/profile/{profile}/rules/{rules}',
                '/pm/config/adom/{adom}/obj/file-filter/profile/{profile}/rules/{rules}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'firewall_accessproxy': {
            'params': [
                'access-proxy',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'firewall_accessproxy6': {
            'params': [
                'access-proxy6',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/access-proxy6/{access-proxy6}',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy6/{access-proxy6}'
            ],
            'revision': {
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'name'
        },
        'firewall_accessproxy6_apigateway': {
            'params': [
                'access-proxy6',
                'api-gateway',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/access-proxy6/{access-proxy6}/api-gateway/{api-gateway}',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy6/{access-proxy6}/api-gateway/{api-gateway}'
            ],
            'revision': {
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'id'
        },
        'firewall_accessproxy6_apigateway6': {
            'params': [
                'access-proxy6',
                'api-gateway6',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/access-proxy6/{access-proxy6}/api-gateway6/{api-gateway6}',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy6/{access-proxy6}/api-gateway6/{api-gateway6}'
            ],
            'revision': {
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'id'
        },
        'firewall_accessproxy6_apigateway6_realservers': {
            'params': [
                'access-proxy6',
                'api-gateway6',
                'realservers',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/access-proxy6/{access-proxy6}/api-gateway6/{api-gateway6}/realservers/{realservers}',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy6/{access-proxy6}/api-gateway6/{api-gateway6}/realservers/{realservers}'
            ],
            'revision': {
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'id'
        },
        'firewall_accessproxy6_apigateway6_sslciphersuites': {
            'params': [
                'access-proxy6',
                'api-gateway6',
                'ssl-cipher-suites',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/access-proxy6/{access-proxy6}/api-gateway6/{api-gateway6}/ssl-cipher-suites/{ssl-cipher-suites}',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy6/{access-proxy6}/api-gateway6/{api-gateway6}/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
            'revision': {
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': None
        },
        'firewall_accessproxy6_apigateway_realservers': {
            'params': [
                'access-proxy6',
                'api-gateway',
                'realservers',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/access-proxy6/{access-proxy6}/api-gateway/{api-gateway}/realservers/{realservers}',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy6/{access-proxy6}/api-gateway/{api-gateway}/realservers/{realservers}'
            ],
            'revision': {
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'id'
        },
        'firewall_accessproxy6_apigateway_sslciphersuites': {
            'params': [
                'access-proxy6',
                'api-gateway',
                'ssl-cipher-suites',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/access-proxy6/{access-proxy6}/api-gateway/{api-gateway}/ssl-cipher-suites/{ssl-cipher-suites}',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy6/{access-proxy6}/api-gateway/{api-gateway}/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
            'revision': {
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': None
        },
        'firewall_accessproxy_apigateway': {
            'params': [
                'access-proxy',
                'api-gateway',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/api-gateway/{api-gateway}',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/api-gateway/{api-gateway}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'firewall_accessproxy_apigateway6': {
            'params': [
                'access-proxy',
                'api-gateway6',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/api-gateway6/{api-gateway6}',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/api-gateway6/{api-gateway6}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'firewall_accessproxy_apigateway6_realservers': {
            'params': [
                'access-proxy',
                'api-gateway6',
                'realservers',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/api-gateway6/{api-gateway6}/realservers/{realservers}',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/api-gateway6/{api-gateway6}/realservers/{realservers}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'firewall_accessproxy_apigateway6_sslciphersuites': {
            'params': [
                'access-proxy',
                'api-gateway6',
                'ssl-cipher-suites',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/api-gateway6/{api-gateway6}/ssl-cipher-suites/{ssl-cipher-suites}',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/api-gateway6/{api-gateway6}/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
            'revision': {
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
            'mkey': None
        },
        'firewall_accessproxy_apigateway_realservers': {
            'params': [
                'access-proxy',
                'api-gateway',
                'realservers',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/api-gateway/{api-gateway}/realservers/{realservers}',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/api-gateway/{api-gateway}/realservers/{realservers}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'firewall_accessproxy_apigateway_sslciphersuites': {
            'params': [
                'access-proxy',
                'api-gateway',
                'ssl-cipher-suites',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/api-gateway/{api-gateway}/ssl-cipher-suites/{ssl-cipher-suites}',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/api-gateway/{api-gateway}/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
            'revision': {
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
            'mkey': None
        },
        'firewall_accessproxy_realservers': {
            'params': [
                'access-proxy',
                'realservers',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/realservers/{realservers}',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/realservers/{realservers}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'firewall_accessproxy_serverpubkeyauthsettings_certextension': {
            'params': [
                'access-proxy',
                'cert-extension',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/server-pubkey-auth-settings/cert-extension/{cert-extension}',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/server-pubkey-auth-settings/cert-extension/{cert-extension}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'firewall_accessproxyvirtualhost': {
            'params': [
                'access-proxy-virtual-host',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/access-proxy-virtual-host/{access-proxy-virtual-host}',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy-virtual-host/{access-proxy-virtual-host}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'firewall_address': {
            'params': [
                'adom',
                'address'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address/{address}',
                '/pm/config/global/obj/firewall/address/{address}'
            ],
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
            'mkey': 'name'
        },
        'firewall_address6': {
            'params': [
                'adom',
                'address6'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}',
                '/pm/config/global/obj/firewall/address6/{address6}'
            ],
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
            'mkey': 'name'
        },
        'firewall_address6_dynamicmapping': {
            'params': [
                'adom',
                'address6',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/address6/{address6}/dynamic_mapping/{dynamic_mapping}'
            ],
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
            'mkey': '_scope'
        },
        'firewall_address6_dynamicmapping_subnetsegment': {
            'params': [
                'address6',
                'dynamic_mapping',
                'subnet-segment',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/address6/{address6}/dynamic_mapping/{dynamic_mapping}/subnet-segment/{subnet-segment}',
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}/dynamic_mapping/{dynamic_mapping}/subnet-segment/{subnet-segment}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'firewall_address6_list': {
            'params': [
                'adom',
                'address6',
                'list'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}/list/{list}',
                '/pm/config/global/obj/firewall/address6/{address6}/list/{list}'
            ],
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
            'mkey': 'ip'
        },
        'firewall_address6_profilelist': {
            'params': [
                'address6',
                'profile-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/address6/{address6}/profile-list/{profile-list}',
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}/profile-list/{profile-list}'
            ],
            'revision': {
                '6.2.0': True,
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.6': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True
            },
            'mkey': None
        },
        'firewall_address6_subnetsegment': {
            'params': [
                'adom',
                'address6',
                'subnet-segment'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}/subnet-segment/{subnet-segment}',
                '/pm/config/global/obj/firewall/address6/{address6}/subnet-segment/{subnet-segment}'
            ],
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
            'mkey': 'name'
        },
        'firewall_address6_tagging': {
            'params': [
                'adom',
                'address6',
                'tagging'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/address6/{address6}/tagging/{tagging}'
            ],
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
            'mkey': 'name'
        },
        'firewall_address6template': {
            'params': [
                'adom',
                'address6-template'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6-template/{address6-template}',
                '/pm/config/global/obj/firewall/address6-template/{address6-template}'
            ],
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
            'mkey': 'name'
        },
        'firewall_address6template_subnetsegment': {
            'params': [
                'adom',
                'address6-template',
                'subnet-segment'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6-template/{address6-template}/subnet-segment/{subnet-segment}',
                '/pm/config/global/obj/firewall/address6-template/{address6-template}/subnet-segment/{subnet-segment}'
            ],
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
            'mkey': 'id'
        },
        'firewall_address6template_subnetsegment_values': {
            'params': [
                'adom',
                'address6-template',
                'subnet-segment',
                'values'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6-template/{address6-template}/subnet-segment/{subnet-segment}/values/{values}',
                '/pm/config/global/obj/firewall/address6-template/{address6-template}/subnet-segment/{subnet-segment}/values/{values}'
            ],
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
            'mkey': 'name'
        },
        'firewall_address_dynamicmapping': {
            'params': [
                'adom',
                'address',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address/{address}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/address/{address}/dynamic_mapping/{dynamic_mapping}'
            ],
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
            'mkey': '_scope'
        },
        'firewall_address_list': {
            'params': [
                'adom',
                'address',
                'list'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address/{address}/list/{list}',
                '/pm/config/global/obj/firewall/address/{address}/list/{list}'
            ],
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
            'mkey': 'ip'
        },
        'firewall_address_profilelist': {
            'params': [
                'address',
                'profile-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/address/{address}/profile-list/{profile-list}',
                '/pm/config/adom/{adom}/obj/firewall/address/{address}/profile-list/{profile-list}'
            ],
            'revision': {
                '6.2.0': True,
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.6': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True
            },
            'mkey': None
        },
        'firewall_address_tagging': {
            'params': [
                'adom',
                'address',
                'tagging'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address/{address}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/address/{address}/tagging/{tagging}'
            ],
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
            'mkey': 'name'
        },
        'firewall_addrgrp': {
            'params': [
                'adom',
                'addrgrp'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/addrgrp/{addrgrp}',
                '/pm/config/global/obj/firewall/addrgrp/{addrgrp}'
            ],
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
            'mkey': 'name'
        },
        'firewall_addrgrp6': {
            'params': [
                'adom',
                'addrgrp6'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/addrgrp6/{addrgrp6}',
                '/pm/config/global/obj/firewall/addrgrp6/{addrgrp6}'
            ],
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
            'mkey': 'name'
        },
        'firewall_addrgrp6_dynamicmapping': {
            'params': [
                'adom',
                'addrgrp6',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/addrgrp6/{addrgrp6}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/addrgrp6/{addrgrp6}/dynamic_mapping/{dynamic_mapping}'
            ],
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
            'mkey': '_scope'
        },
        'firewall_addrgrp6_tagging': {
            'params': [
                'adom',
                'addrgrp6',
                'tagging'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/addrgrp6/{addrgrp6}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/addrgrp6/{addrgrp6}/tagging/{tagging}'
            ],
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
            'mkey': 'name'
        },
        'firewall_addrgrp_dynamicmapping': {
            'params': [
                'adom',
                'addrgrp',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/addrgrp/{addrgrp}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/addrgrp/{addrgrp}/dynamic_mapping/{dynamic_mapping}'
            ],
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
            'mkey': '_scope'
        },
        'firewall_addrgrp_tagging': {
            'params': [
                'adom',
                'addrgrp',
                'tagging'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/addrgrp/{addrgrp}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/addrgrp/{addrgrp}/tagging/{tagging}'
            ],
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
            'mkey': 'name'
        },
        'firewall_carrierendpointbwl': {
            'params': [
                'adom',
                'carrier-endpoint-bwl'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/carrier-endpoint-bwl/{carrier-endpoint-bwl}',
                '/pm/config/global/obj/firewall/carrier-endpoint-bwl/{carrier-endpoint-bwl}'
            ],
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
            'mkey': 'id'
        },
        'firewall_carrierendpointbwl_entries': {
            'params': [
                'adom',
                'carrier-endpoint-bwl',
                'entries'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/carrier-endpoint-bwl/{carrier-endpoint-bwl}/entries/{entries}',
                '/pm/config/global/obj/firewall/carrier-endpoint-bwl/{carrier-endpoint-bwl}/entries/{entries}'
            ],
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
            'mkey': 'carrier-endpoint'
        },
        'firewall_decryptedtrafficmirror': {
            'params': [
                'decrypted-traffic-mirror',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/decrypted-traffic-mirror/{decrypted-traffic-mirror}',
                '/pm/config/adom/{adom}/obj/firewall/decrypted-traffic-mirror/{decrypted-traffic-mirror}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'firewall_explicitproxyaddress': {
            'params': [
                'explicit-proxy-address',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/explicit-proxy-address/{explicit-proxy-address}',
                '/pm/config/adom/{adom}/obj/firewall/explicit-proxy-address/{explicit-proxy-address}'
            ],
            'revision': {
                '6.2.0': True,
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.6': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True
            },
            'mkey': 'name'
        },
        'firewall_explicitproxyaddress_headergroup': {
            'params': [
                'explicit-proxy-address',
                'header-group',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/explicit-proxy-address/{explicit-proxy-address}/header-group/{header-group}',
                '/pm/config/adom/{adom}/obj/firewall/explicit-proxy-address/{explicit-proxy-address}/header-group/{header-group}'
            ],
            'revision': {
                '6.2.0': True,
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.6': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True
            },
            'mkey': 'id'
        },
        'firewall_explicitproxyaddrgrp': {
            'params': [
                'explicit-proxy-addrgrp',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/explicit-proxy-addrgrp/{explicit-proxy-addrgrp}',
                '/pm/config/adom/{adom}/obj/firewall/explicit-proxy-addrgrp/{explicit-proxy-addrgrp}'
            ],
            'revision': {
                '6.2.0': True,
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.6': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True
            },
            'mkey': 'name'
        },
        'firewall_gtp': {
            'params': [
                'adom',
                'gtp'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}',
                '/pm/config/global/obj/firewall/gtp/{gtp}'
            ],
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
            'mkey': 'name'
        },
        'firewall_gtp_apn': {
            'params': [
                'adom',
                'gtp',
                'apn'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/apn/{apn}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/apn/{apn}'
            ],
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
            'mkey': 'id'
        },
        'firewall_gtp_ieremovepolicy': {
            'params': [
                'adom',
                'gtp',
                'ie-remove-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/ie-remove-policy/{ie-remove-policy}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/ie-remove-policy/{ie-remove-policy}'
            ],
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
            'mkey': 'id'
        },
        'firewall_gtp_imsi': {
            'params': [
                'adom',
                'gtp',
                'imsi'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/imsi/{imsi}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/imsi/{imsi}'
            ],
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
            'mkey': 'id'
        },
        'firewall_gtp_ippolicy': {
            'params': [
                'adom',
                'gtp',
                'ip-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/ip-policy/{ip-policy}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/ip-policy/{ip-policy}'
            ],
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
            'mkey': 'id'
        },
        'firewall_gtp_noippolicy': {
            'params': [
                'adom',
                'gtp',
                'noip-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/noip-policy/{noip-policy}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/noip-policy/{noip-policy}'
            ],
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
            'mkey': 'id'
        },
        'firewall_gtp_perapnshaper': {
            'params': [
                'adom',
                'gtp',
                'per-apn-shaper'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/per-apn-shaper/{per-apn-shaper}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/per-apn-shaper/{per-apn-shaper}'
            ],
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
            'mkey': 'id'
        },
        'firewall_gtp_policy': {
            'params': [
                'adom',
                'gtp',
                'policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/policy/{policy}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/policy/{policy}'
            ],
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
            'mkey': 'id'
        },
        'firewall_gtp_policyv2': {
            'params': [
                'gtp',
                'policy-v2',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/gtp/{gtp}/policy-v2/{policy-v2}',
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/policy-v2/{policy-v2}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'firewall_identitybasedroute': {
            'params': [
                'adom',
                'identity-based-route'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/identity-based-route/{identity-based-route}',
                '/pm/config/global/obj/firewall/identity-based-route/{identity-based-route}'
            ],
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
            'mkey': 'name'
        },
        'firewall_identitybasedroute_rule': {
            'params': [
                'adom',
                'identity-based-route',
                'rule'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/identity-based-route/{identity-based-route}/rule/{rule}',
                '/pm/config/global/obj/firewall/identity-based-route/{identity-based-route}/rule/{rule}'
            ],
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
            'mkey': 'id'
        },
        'firewall_internetservice_entry': {
            'params': [
                'adom',
                'entry'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service/entry/{entry}',
                '/pm/config/global/obj/firewall/internet-service/entry/{entry}'
            ],
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
                '7.2.1': True
            },
            'mkey': 'id'
        },
        'firewall_internetserviceaddition': {
            'params': [
                'internet-service-addition',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/internet-service-addition/{internet-service-addition}',
                '/pm/config/adom/{adom}/obj/firewall/internet-service-addition/{internet-service-addition}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'firewall_internetserviceaddition_entry': {
            'params': [
                'internet-service-addition',
                'entry',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/internet-service-addition/{internet-service-addition}/entry/{entry}',
                '/pm/config/adom/{adom}/obj/firewall/internet-service-addition/{internet-service-addition}/entry/{entry}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'firewall_internetserviceaddition_entry_portrange': {
            'params': [
                'internet-service-addition',
                'entry',
                'port-range',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/internet-service-addition/{internet-service-addition}/entry/{entry}/port-range/{port-range}',
                '/pm/config/adom/{adom}/obj/firewall/internet-service-addition/{internet-service-addition}/entry/{entry}/port-range/{port-range}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'firewall_internetservicecustom': {
            'params': [
                'adom',
                'internet-service-custom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom/{internet-service-custom}',
                '/pm/config/global/obj/firewall/internet-service-custom/{internet-service-custom}'
            ],
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
            'mkey': 'id'
        },
        'firewall_internetservicecustom_disableentry': {
            'params': [
                'adom',
                'internet-service-custom',
                'disable-entry'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}',
                '/pm/config/global/obj/firewall/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}'
            ],
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
                '7.2.1': True
            },
            'mkey': 'id'
        },
        'firewall_internetservicecustom_disableentry_iprange': {
            'params': [
                'adom',
                'internet-service-custom',
                'disable-entry',
                'ip-range'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}/ip-range/{ip-range}',
                '/pm/config/global/obj/firewall/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}/ip-range/{ip-range}'
            ],
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
                '7.2.1': True
            },
            'mkey': 'id'
        },
        'firewall_internetservicecustom_entry': {
            'params': [
                'adom',
                'internet-service-custom',
                'entry'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom/{internet-service-custom}/entry/{entry}',
                '/pm/config/global/obj/firewall/internet-service-custom/{internet-service-custom}/entry/{entry}'
            ],
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
            'mkey': 'id'
        },
        'firewall_internetservicecustom_entry_portrange': {
            'params': [
                'adom',
                'internet-service-custom',
                'entry',
                'port-range'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom/{internet-service-custom}/entry/{entry}/port-range/{port-range}',
                '/pm/config/global/obj/firewall/internet-service-custom/{internet-service-custom}/entry/{entry}/port-range/{port-range}'
            ],
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
            'mkey': 'id'
        },
        'firewall_internetservicecustomgroup': {
            'params': [
                'adom',
                'internet-service-custom-group'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom-group/{internet-service-custom-group}',
                '/pm/config/global/obj/firewall/internet-service-custom-group/{internet-service-custom-group}'
            ],
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
            'mkey': 'name'
        },
        'firewall_internetservicegroup': {
            'params': [
                'adom',
                'internet-service-group'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-group/{internet-service-group}',
                '/pm/config/global/obj/firewall/internet-service-group/{internet-service-group}'
            ],
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
            'mkey': 'name'
        },
        'firewall_internetservicename': {
            'params': [
                'internet-service-name',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/internet-service-name/{internet-service-name}',
                '/pm/config/adom/{adom}/obj/firewall/internet-service-name/{internet-service-name}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'firewall_ippool': {
            'params': [
                'adom',
                'ippool'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ippool/{ippool}',
                '/pm/config/global/obj/firewall/ippool/{ippool}'
            ],
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
            'mkey': 'name'
        },
        'firewall_ippool6': {
            'params': [
                'adom',
                'ippool6'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ippool6/{ippool6}',
                '/pm/config/global/obj/firewall/ippool6/{ippool6}'
            ],
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
            'mkey': 'name'
        },
        'firewall_ippool6_dynamicmapping': {
            'params': [
                'adom',
                'ippool6',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ippool6/{ippool6}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/ippool6/{ippool6}/dynamic_mapping/{dynamic_mapping}'
            ],
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
            'mkey': '_scope'
        },
        'firewall_ippool_dynamicmapping': {
            'params': [
                'adom',
                'ippool',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ippool/{ippool}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/ippool/{ippool}/dynamic_mapping/{dynamic_mapping}'
            ],
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
            'mkey': '_scope'
        },
        'firewall_ippoolgrp': {
            'params': [
                'ippool_grp',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/ippool_grp/{ippool_grp}',
                '/pm/config/adom/{adom}/obj/firewall/ippool_grp/{ippool_grp}'
            ],
            'revision': {
                '6.4.7': True,
                '6.4.8': True,
                '6.4.9': True,
                '6.4.10': True,
                '6.4.11': True,
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
            'mkey': 'name'
        },
        'firewall_ldbmonitor': {
            'params': [
                'adom',
                'ldb-monitor'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ldb-monitor/{ldb-monitor}',
                '/pm/config/global/obj/firewall/ldb-monitor/{ldb-monitor}'
            ],
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
            'mkey': 'name'
        },
        'firewall_mmsprofile': {
            'params': [
                'adom',
                'mms-profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/mms-profile/{mms-profile}',
                '/pm/config/global/obj/firewall/mms-profile/{mms-profile}'
            ],
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
            'mkey': 'name'
        },
        'firewall_mmsprofile_notifmsisdn': {
            'params': [
                'adom',
                'mms-profile',
                'notif-msisdn'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/mms-profile/{mms-profile}/notif-msisdn/{notif-msisdn}',
                '/pm/config/global/obj/firewall/mms-profile/{mms-profile}/notif-msisdn/{notif-msisdn}'
            ],
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
            'mkey': 'msisdn'
        },
        'firewall_multicastaddress': {
            'params': [
                'adom',
                'multicast-address'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/multicast-address/{multicast-address}',
                '/pm/config/global/obj/firewall/multicast-address/{multicast-address}'
            ],
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
            'mkey': 'name'
        },
        'firewall_multicastaddress6': {
            'params': [
                'adom',
                'multicast-address6'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/multicast-address6/{multicast-address6}',
                '/pm/config/global/obj/firewall/multicast-address6/{multicast-address6}'
            ],
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
            'mkey': 'name'
        },
        'firewall_multicastaddress6_tagging': {
            'params': [
                'adom',
                'multicast-address6',
                'tagging'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/multicast-address6/{multicast-address6}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/multicast-address6/{multicast-address6}/tagging/{tagging}'
            ],
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
            'mkey': 'name'
        },
        'firewall_multicastaddress_tagging': {
            'params': [
                'adom',
                'multicast-address',
                'tagging'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/multicast-address/{multicast-address}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/multicast-address/{multicast-address}/tagging/{tagging}'
            ],
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
            'mkey': 'name'
        },
        'firewall_networkservicedynamic': {
            'params': [
                'network-service-dynamic',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/network-service-dynamic/{network-service-dynamic}',
                '/pm/config/adom/{adom}/obj/firewall/network-service-dynamic/{network-service-dynamic}'
            ],
            'revision': {
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'id'
        },
        'firewall_profilegroup': {
            'params': [
                'adom',
                'profile-group'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-group/{profile-group}',
                '/pm/config/global/obj/firewall/profile-group/{profile-group}'
            ],
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
            'mkey': 'name'
        },
        'firewall_profileprotocoloptions': {
            'params': [
                'adom',
                'profile-protocol-options'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}',
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}'
            ],
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
            'mkey': 'name'
        },
        'firewall_profileprotocoloptions_cifs_filefilter_entries': {
            'params': [
                'profile-protocol-options',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/cifs/file-filter/entries/{entries}',
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/cifs/file-filter/entries/{entries}'
            ],
            'revision': {
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
            'mkey': None
        },
        'firewall_profileprotocoloptions_cifs_serverkeytab': {
            'params': [
                'profile-protocol-options',
                'server-keytab',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/cifs/server-keytab/{server-keytab}',
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/cifs/server-keytab/{server-keytab}'
            ],
            'revision': {
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
            'mkey': None
        },
        'firewall_proxyaddress': {
            'params': [
                'adom',
                'proxy-address'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/proxy-address/{proxy-address}',
                '/pm/config/global/obj/firewall/proxy-address/{proxy-address}'
            ],
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
            'mkey': 'name'
        },
        'firewall_proxyaddress_headergroup': {
            'params': [
                'adom',
                'proxy-address',
                'header-group'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/proxy-address/{proxy-address}/header-group/{header-group}',
                '/pm/config/global/obj/firewall/proxy-address/{proxy-address}/header-group/{header-group}'
            ],
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
            'mkey': 'id'
        },
        'firewall_proxyaddress_tagging': {
            'params': [
                'adom',
                'proxy-address',
                'tagging'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/proxy-address/{proxy-address}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/proxy-address/{proxy-address}/tagging/{tagging}'
            ],
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
            'mkey': 'name'
        },
        'firewall_proxyaddrgrp': {
            'params': [
                'adom',
                'proxy-addrgrp'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/proxy-addrgrp/{proxy-addrgrp}',
                '/pm/config/global/obj/firewall/proxy-addrgrp/{proxy-addrgrp}'
            ],
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
            'mkey': 'name'
        },
        'firewall_proxyaddrgrp_tagging': {
            'params': [
                'adom',
                'proxy-addrgrp',
                'tagging'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/proxy-addrgrp/{proxy-addrgrp}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/proxy-addrgrp/{proxy-addrgrp}/tagging/{tagging}'
            ],
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
            'mkey': 'name'
        },
        'firewall_schedule_group': {
            'params': [
                'adom',
                'group'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/schedule/group/{group}',
                '/pm/config/global/obj/firewall/schedule/group/{group}'
            ],
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
            'mkey': 'name'
        },
        'firewall_schedule_onetime': {
            'params': [
                'adom',
                'onetime'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/schedule/onetime/{onetime}',
                '/pm/config/global/obj/firewall/schedule/onetime/{onetime}'
            ],
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
            'mkey': 'name'
        },
        'firewall_schedule_recurring': {
            'params': [
                'adom',
                'recurring'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/schedule/recurring/{recurring}',
                '/pm/config/global/obj/firewall/schedule/recurring/{recurring}'
            ],
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
            'mkey': 'name'
        },
        'firewall_service_category': {
            'params': [
                'adom',
                'category'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/service/category/{category}',
                '/pm/config/global/obj/firewall/service/category/{category}'
            ],
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
            'mkey': 'name'
        },
        'firewall_service_custom': {
            'params': [
                'adom',
                'custom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/service/custom/{custom}',
                '/pm/config/global/obj/firewall/service/custom/{custom}'
            ],
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
            'mkey': 'name'
        },
        'firewall_service_group': {
            'params': [
                'adom',
                'group'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/service/group/{group}',
                '/pm/config/global/obj/firewall/service/group/{group}'
            ],
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
            'mkey': 'name'
        },
        'firewall_shaper_peripshaper': {
            'params': [
                'adom',
                'per-ip-shaper'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/shaper/per-ip-shaper/{per-ip-shaper}',
                '/pm/config/global/obj/firewall/shaper/per-ip-shaper/{per-ip-shaper}'
            ],
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
            'mkey': 'name'
        },
        'firewall_shaper_trafficshaper': {
            'params': [
                'adom',
                'traffic-shaper'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/shaper/traffic-shaper/{traffic-shaper}',
                '/pm/config/global/obj/firewall/shaper/traffic-shaper/{traffic-shaper}'
            ],
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
            'mkey': 'name'
        },
        'firewall_shapingprofile': {
            'params': [
                'adom',
                'shaping-profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/shaping-profile/{shaping-profile}',
                '/pm/config/global/obj/firewall/shaping-profile/{shaping-profile}'
            ],
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
            'mkey': 'profile-name'
        },
        'firewall_shapingprofile_shapingentries': {
            'params': [
                'adom',
                'shaping-profile',
                'shaping-entries'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/shaping-profile/{shaping-profile}/shaping-entries/{shaping-entries}',
                '/pm/config/global/obj/firewall/shaping-profile/{shaping-profile}/shaping-entries/{shaping-entries}'
            ],
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
            'mkey': 'id'
        },
        'firewall_ssh_localca': {
            'params': [
                'local-ca',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/ssh/local-ca/{local-ca}',
                '/pm/config/adom/{adom}/obj/firewall/ssh/local-ca/{local-ca}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'firewall_sslsshprofile': {
            'params': [
                'adom',
                'ssl-ssh-profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}',
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}'
            ],
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
            'mkey': 'name'
        },
        'firewall_sslsshprofile_sslexempt': {
            'params': [
                'adom',
                'ssl-ssh-profile',
                'ssl-exempt'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl-exempt/{ssl-exempt}',
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl-exempt/{ssl-exempt}'
            ],
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
            'mkey': 'id'
        },
        'firewall_sslsshprofile_sslserver': {
            'params': [
                'adom',
                'ssl-ssh-profile',
                'ssl-server'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl-server/{ssl-server}',
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl-server/{ssl-server}'
            ],
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
            'mkey': 'id'
        },
        'firewall_trafficclass': {
            'params': [
                'traffic-class',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/traffic-class/{traffic-class}',
                '/pm/config/adom/{adom}/obj/firewall/traffic-class/{traffic-class}'
            ],
            'revision': {
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
            'mkey': None
        },
        'firewall_vip': {
            'params': [
                'adom',
                'vip'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}',
                '/pm/config/global/obj/firewall/vip/{vip}'
            ],
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
            'mkey': 'name'
        },
        'firewall_vip46': {
            'params': [
                'adom',
                'vip46'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip46/{vip46}',
                '/pm/config/global/obj/firewall/vip46/{vip46}'
            ],
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
            'mkey': 'name'
        },
        'firewall_vip46_dynamicmapping': {
            'params': [
                'adom',
                'vip46',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip46/{vip46}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/vip46/{vip46}/dynamic_mapping/{dynamic_mapping}'
            ],
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
            'mkey': '_scope'
        },
        'firewall_vip46_realservers': {
            'params': [
                'adom',
                'vip46',
                'realservers'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip46/{vip46}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/vip46/{vip46}/realservers/{realservers}'
            ],
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
            'mkey': 'id'
        },
        'firewall_vip6': {
            'params': [
                'adom',
                'vip6'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}',
                '/pm/config/global/obj/firewall/vip6/{vip6}'
            ],
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
            'mkey': 'name'
        },
        'firewall_vip64': {
            'params': [
                'adom',
                'vip64'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip64/{vip64}',
                '/pm/config/global/obj/firewall/vip64/{vip64}'
            ],
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
            'mkey': 'name'
        },
        'firewall_vip64_dynamicmapping': {
            'params': [
                'adom',
                'vip64',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip64/{vip64}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/vip64/{vip64}/dynamic_mapping/{dynamic_mapping}'
            ],
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
            'mkey': '_scope'
        },
        'firewall_vip64_realservers': {
            'params': [
                'adom',
                'vip64',
                'realservers'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip64/{vip64}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/vip64/{vip64}/realservers/{realservers}'
            ],
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
            'mkey': 'id'
        },
        'firewall_vip6_dynamicmapping': {
            'params': [
                'adom',
                'vip6',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}'
            ],
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
            'mkey': '_scope'
        },
        'firewall_vip6_dynamicmapping_realservers': {
            'params': [
                'vip6',
                'dynamic_mapping',
                'realservers',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}/realservers/{realservers}',
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}/realservers/{realservers}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'firewall_vip6_dynamicmapping_sslciphersuites': {
            'params': [
                'vip6',
                'dynamic_mapping',
                'ssl-cipher-suites',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}/ssl-cipher-suites/{ssl-cipher-suites}',
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
            'revision': {
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
            'mkey': None
        },
        'firewall_vip6_realservers': {
            'params': [
                'adom',
                'vip6',
                'realservers'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/vip6/{vip6}/realservers/{realservers}'
            ],
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
            'mkey': 'id'
        },
        'firewall_vip6_sslciphersuites': {
            'params': [
                'adom',
                'vip6',
                'ssl-cipher-suites'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/ssl-cipher-suites/{ssl-cipher-suites}',
                '/pm/config/global/obj/firewall/vip6/{vip6}/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
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
            'mkey': 'priority'
        },
        'firewall_vip6_sslserverciphersuites': {
            'params': [
                'adom',
                'vip6',
                'ssl-server-cipher-suites'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/ssl-server-cipher-suites/{ssl-server-cipher-suites}',
                '/pm/config/global/obj/firewall/vip6/{vip6}/ssl-server-cipher-suites/{ssl-server-cipher-suites}'
            ],
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
            'mkey': 'priority'
        },
        'firewall_vip_dynamicmapping': {
            'params': [
                'adom',
                'vip',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}'
            ],
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
            'mkey': '_scope'
        },
        'firewall_vip_dynamicmapping_realservers': {
            'params': [
                'adom',
                'vip',
                'dynamic_mapping',
                'realservers'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}/realservers/{realservers}'
            ],
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
            'mkey': 'seq'
        },
        'firewall_vip_dynamicmapping_sslciphersuites': {
            'params': [
                'adom',
                'vip',
                'dynamic_mapping',
                'ssl-cipher-suites'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}/ssl-cipher-suites/{ssl-cipher-suites}',
                '/pm/config/global/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
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
            'mkey': 'id'
        },
        'firewall_vip_realservers': {
            'params': [
                'adom',
                'vip',
                'realservers'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/vip/{vip}/realservers/{realservers}'
            ],
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
            'mkey': 'seq'
        },
        'firewall_vip_sslciphersuites': {
            'params': [
                'adom',
                'vip',
                'ssl-cipher-suites'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/ssl-cipher-suites/{ssl-cipher-suites}',
                '/pm/config/global/obj/firewall/vip/{vip}/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
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
            'mkey': 'id'
        },
        'firewall_vip_sslserverciphersuites': {
            'params': [
                'adom',
                'vip',
                'ssl-server-cipher-suites'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/ssl-server-cipher-suites/{ssl-server-cipher-suites}',
                '/pm/config/global/obj/firewall/vip/{vip}/ssl-server-cipher-suites/{ssl-server-cipher-suites}'
            ],
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
            'mkey': 'priority'
        },
        'firewall_vipgrp': {
            'params': [
                'adom',
                'vipgrp'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vipgrp/{vipgrp}',
                '/pm/config/global/obj/firewall/vipgrp/{vipgrp}'
            ],
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
            'mkey': 'name'
        },
        'firewall_vipgrp46': {
            'params': [
                'adom',
                'vipgrp46'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vipgrp46/{vipgrp46}',
                '/pm/config/global/obj/firewall/vipgrp46/{vipgrp46}'
            ],
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
            'mkey': 'name'
        },
        'firewall_vipgrp6': {
            'params': [
                'adom',
                'vipgrp6'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vipgrp6/{vipgrp6}',
                '/pm/config/global/obj/firewall/vipgrp6/{vipgrp6}'
            ],
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
            'mkey': 'name'
        },
        'firewall_vipgrp64': {
            'params': [
                'adom',
                'vipgrp64'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vipgrp64/{vipgrp64}',
                '/pm/config/global/obj/firewall/vipgrp64/{vipgrp64}'
            ],
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
            'mkey': 'name'
        },
        'firewall_vipgrp_dynamicmapping': {
            'params': [
                'adom',
                'vipgrp',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vipgrp/{vipgrp}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/vipgrp/{vipgrp}/dynamic_mapping/{dynamic_mapping}'
            ],
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
            'mkey': '_scope'
        },
        'firewall_wildcardfqdn_custom': {
            'params': [
                'adom',
                'custom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/wildcard-fqdn/custom/{custom}',
                '/pm/config/global/obj/firewall/wildcard-fqdn/custom/{custom}'
            ],
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
            'mkey': 'name'
        },
        'firewall_wildcardfqdn_group': {
            'params': [
                'adom',
                'group'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/wildcard-fqdn/group/{group}',
                '/pm/config/global/obj/firewall/wildcard-fqdn/group/{group}'
            ],
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
            'mkey': 'name'
        },
        'fmg_device_blueprint': {
            'params': [
                'blueprint',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/fmg/device/blueprint/{blueprint}',
                '/pm/config/adom/{adom}/obj/fmg/device/blueprint/{blueprint}'
            ],
            'revision': {
                '7.2.0': True,
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'name'
        },
        'fmg_fabric_authorization_template': {
            'params': [
                'template',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/fmg/fabric/authorization/template/{template}',
                '/pm/config/adom/{adom}/obj/fmg/fabric/authorization/template/{template}'
            ],
            'revision': {
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'name'
        },
        'fmg_fabric_authorization_template_platforms': {
            'params': [
                'template',
                'platforms',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/fmg/fabric/authorization/template/{template}/platforms/{platforms}',
                '/pm/config/adom/{adom}/obj/fmg/fabric/authorization/template/{template}/platforms/{platforms}'
            ],
            'revision': {
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': None
        },
        'fmg_variable': {
            'params': [
                'variable',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/fmg/variable/{variable}',
                '/pm/config/adom/{adom}/obj/fmg/variable/{variable}'
            ],
            'revision': {
                '7.2.0': True,
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'name'
        },
        'fmg_variable_dynamicmapping': {
            'params': [
                'variable',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/fmg/variable/{variable}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/adom/{adom}/obj/fmg/variable/{variable}/dynamic_mapping/{dynamic_mapping}'
            ],
            'revision': {
                '7.2.0': True,
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': None
        },
        'fsp_vlan': {
            'params': [
                'adom',
                'vlan'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}',
                '/pm/config/global/obj/fsp/vlan/{vlan}'
            ],
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
            'mkey': 'name'
        },
        'fsp_vlan_dhcpserver_excluderange': {
            'params': [
                'adom',
                'vlan',
                'exclude-range'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dhcp-server/exclude-range/{exclude-range}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dhcp-server/exclude-range/{exclude-range}'
            ],
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
            'mkey': 'id'
        },
        'fsp_vlan_dhcpserver_iprange': {
            'params': [
                'adom',
                'vlan',
                'ip-range'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dhcp-server/ip-range/{ip-range}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dhcp-server/ip-range/{ip-range}'
            ],
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
            'mkey': 'id'
        },
        'fsp_vlan_dhcpserver_options': {
            'params': [
                'adom',
                'vlan',
                'options'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dhcp-server/options/{options}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dhcp-server/options/{options}'
            ],
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
            'mkey': 'id'
        },
        'fsp_vlan_dhcpserver_reservedaddress': {
            'params': [
                'adom',
                'vlan',
                'reserved-address'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dhcp-server/reserved-address/{reserved-address}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dhcp-server/reserved-address/{reserved-address}'
            ],
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
            'mkey': 'id'
        },
        'fsp_vlan_dynamicmapping': {
            'params': [
                'adom',
                'vlan',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}'
            ],
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
            'mkey': None
        },
        'fsp_vlan_dynamicmapping_dhcpserver_excluderange': {
            'params': [
                'adom',
                'vlan',
                'dynamic_mapping',
                'exclude-range'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/exclude-range/{exclude-range}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/exclude-range/{exclude-range}'
            ],
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
            'mkey': 'id'
        },
        'fsp_vlan_dynamicmapping_dhcpserver_iprange': {
            'params': [
                'adom',
                'vlan',
                'dynamic_mapping',
                'ip-range'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/ip-range/{ip-range}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/ip-range/{ip-range}'
            ],
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
            'mkey': 'id'
        },
        'fsp_vlan_dynamicmapping_dhcpserver_options': {
            'params': [
                'adom',
                'vlan',
                'dynamic_mapping',
                'options'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/options/{options}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/options/{options}'
            ],
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
            'mkey': 'id'
        },
        'fsp_vlan_dynamicmapping_dhcpserver_reservedaddress': {
            'params': [
                'adom',
                'vlan',
                'dynamic_mapping',
                'reserved-address'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/reserved-address/{reserved-address}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/reserved-address/{reserved-address}'
            ],
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
            'mkey': 'id'
        },
        'fsp_vlan_dynamicmapping_interface_ipv6_ip6delegatedprefixlist': {
            'params': [
                'vlan',
                'dynamic_mapping',
                'ip6-delegated-prefix-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/ip6-delegated-prefix-list/{ip6-delegated-prefix-list}',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/ip6-delegated-prefix-list/{ip6-delegated-prefix-list}'
            ],
            'revision': {
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
            'mkey': None
        },
        'fsp_vlan_dynamicmapping_interface_ipv6_ip6extraaddr': {
            'params': [
                'vlan',
                'dynamic_mapping',
                'ip6-extra-addr',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/ip6-extra-addr/{ip6-extra-addr}',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/ip6-extra-addr/{ip6-extra-addr}'
            ],
            'revision': {
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
            'mkey': None
        },
        'fsp_vlan_dynamicmapping_interface_ipv6_ip6prefixlist': {
            'params': [
                'vlan',
                'dynamic_mapping',
                'ip6-prefix-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/ip6-prefix-list/{ip6-prefix-list}',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/ip6-prefix-list/{ip6-prefix-list}'
            ],
            'revision': {
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
            'mkey': None
        },
        'fsp_vlan_dynamicmapping_interface_ipv6_vrrp6': {
            'params': [
                'vlan',
                'dynamic_mapping',
                'vrrp6',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/vrrp6/{vrrp6}',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/vrrp6/{vrrp6}'
            ],
            'revision': {
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
            'mkey': None
        },
        'fsp_vlan_dynamicmapping_interface_secondaryip': {
            'params': [
                'vlan',
                'dynamic_mapping',
                'secondaryip',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/secondaryip/{secondaryip}',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/secondaryip/{secondaryip}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'fsp_vlan_dynamicmapping_interface_vrrp': {
            'params': [
                'vlan',
                'dynamic_mapping',
                'vrrp',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/vrrp/{vrrp}',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/vrrp/{vrrp}'
            ],
            'revision': {
                '7.4.0': True
            },
            'mkey': None
        },
        'fsp_vlan_dynamicmapping_interface_vrrp_proxyarp': {
            'params': [
                'vlan',
                'dynamic_mapping',
                'vrrp',
                'proxy-arp',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/vrrp/{vrrp}/proxy-arp/{proxy-arp}',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/vrrp/{vrrp}/proxy-arp/{proxy-arp}'
            ],
            'revision': {
                '7.4.0': True
            },
            'mkey': 'id'
        },
        'fsp_vlan_interface_ipv6_ip6delegatedprefixlist': {
            'params': [
                'vlan',
                'ip6-delegated-prefix-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/ipv6/ip6-delegated-prefix-list/{ip6-delegated-prefix-list}',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/ipv6/ip6-delegated-prefix-list/{ip6-delegated-prefix-list}'
            ],
            'revision': {
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
            'mkey': None
        },
        'fsp_vlan_interface_ipv6_ip6extraaddr': {
            'params': [
                'vlan',
                'ip6-extra-addr',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/ipv6/ip6-extra-addr/{ip6-extra-addr}',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/ipv6/ip6-extra-addr/{ip6-extra-addr}'
            ],
            'revision': {
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
            'mkey': None
        },
        'fsp_vlan_interface_ipv6_ip6prefixlist': {
            'params': [
                'vlan',
                'ip6-prefix-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/ipv6/ip6-prefix-list/{ip6-prefix-list}',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/ipv6/ip6-prefix-list/{ip6-prefix-list}'
            ],
            'revision': {
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
            'mkey': None
        },
        'fsp_vlan_interface_ipv6_vrrp6': {
            'params': [
                'vlan',
                'vrrp6',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/ipv6/vrrp6/{vrrp6}',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/ipv6/vrrp6/{vrrp6}'
            ],
            'revision': {
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
            'mkey': None
        },
        'fsp_vlan_interface_secondaryip': {
            'params': [
                'adom',
                'vlan',
                'secondaryip'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/secondaryip/{secondaryip}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/secondaryip/{secondaryip}'
            ],
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
            'mkey': 'id'
        },
        'fsp_vlan_interface_vrrp': {
            'params': [
                'adom',
                'vlan',
                'vrrp'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/vrrp/{vrrp}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/vrrp/{vrrp}'
            ],
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
            'mkey': 'vrid'
        },
        'fsp_vlan_interface_vrrp_proxyarp': {
            'params': [
                'vlan',
                'vrrp',
                'proxy-arp',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/vrrp/{vrrp}/proxy-arp/{proxy-arp}',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/vrrp/{vrrp}/proxy-arp/{proxy-arp}'
            ],
            'revision': {
                '7.4.0': True
            },
            'mkey': 'id'
        },
        'gtp_apn': {
            'params': [
                'adom',
                'apn'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/apn/{apn}',
                '/pm/config/global/obj/gtp/apn/{apn}'
            ],
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
            'mkey': 'name'
        },
        'gtp_apngrp': {
            'params': [
                'adom',
                'apngrp'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/apngrp/{apngrp}',
                '/pm/config/global/obj/gtp/apngrp/{apngrp}'
            ],
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
            'mkey': 'name'
        },
        'gtp_iewhitelist': {
            'params': [
                'adom',
                'ie-white-list'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/ie-white-list/{ie-white-list}',
                '/pm/config/global/obj/gtp/ie-white-list/{ie-white-list}'
            ],
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
            'mkey': 'name'
        },
        'gtp_iewhitelist_entries': {
            'params': [
                'adom',
                'ie-white-list',
                'entries'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/ie-white-list/{ie-white-list}/entries/{entries}',
                '/pm/config/global/obj/gtp/ie-white-list/{ie-white-list}/entries/{entries}'
            ],
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
            'mkey': 'id'
        },
        'gtp_messagefilterv0v1': {
            'params': [
                'adom',
                'message-filter-v0v1'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/message-filter-v0v1/{message-filter-v0v1}',
                '/pm/config/global/obj/gtp/message-filter-v0v1/{message-filter-v0v1}'
            ],
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
            'mkey': 'name'
        },
        'gtp_messagefilterv2': {
            'params': [
                'adom',
                'message-filter-v2'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/message-filter-v2/{message-filter-v2}',
                '/pm/config/global/obj/gtp/message-filter-v2/{message-filter-v2}'
            ],
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
            'mkey': 'name'
        },
        'gtp_tunnellimit': {
            'params': [
                'adom',
                'tunnel-limit'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/tunnel-limit/{tunnel-limit}',
                '/pm/config/global/obj/gtp/tunnel-limit/{tunnel-limit}'
            ],
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
            'mkey': 'name'
        },
        'hotspot20_anqp3gppcellular': {
            'params': [
                'adom',
                'anqp-3gpp-cellular'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-3gpp-cellular/{anqp-3gpp-cellular}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-3gpp-cellular/{anqp-3gpp-cellular}'
            ],
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
            'mkey': 'name'
        },
        'hotspot20_anqp3gppcellular_mccmnclist': {
            'params': [
                'adom',
                'anqp-3gpp-cellular',
                'mcc-mnc-list'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-3gpp-cellular/{anqp-3gpp-cellular}/mcc-mnc-list/{mcc-mnc-list}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-3gpp-cellular/{anqp-3gpp-cellular}/mcc-mnc-list/{mcc-mnc-list}'
            ],
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
            'mkey': 'id'
        },
        'hotspot20_anqpipaddresstype': {
            'params': [
                'adom',
                'anqp-ip-address-type'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-ip-address-type/{anqp-ip-address-type}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-ip-address-type/{anqp-ip-address-type}'
            ],
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
            'mkey': 'name'
        },
        'hotspot20_anqpnairealm': {
            'params': [
                'adom',
                'anqp-nai-realm'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}'
            ],
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
            'mkey': 'name'
        },
        'hotspot20_anqpnairealm_nailist': {
            'params': [
                'adom',
                'anqp-nai-realm',
                'nai-list'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}'
            ],
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
            'mkey': 'name'
        },
        'hotspot20_anqpnairealm_nailist_eapmethod': {
            'params': [
                'adom',
                'anqp-nai-realm',
                'nai-list',
                'eap-method'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method/{eap-method}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method/{eap-method}'
            ],
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
            'mkey': 'index'
        },
        'hotspot20_anqpnairealm_nailist_eapmethod_authparam': {
            'params': [
                'adom',
                'anqp-nai-realm',
                'nai-list',
                'eap-method',
                'auth-param'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method/{eap-method}/auth-param/{auth-param}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method/{eap-method}/auth-param/{auth-param}'
            ],
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
            'mkey': 'id'
        },
        'hotspot20_anqpnetworkauthtype': {
            'params': [
                'adom',
                'anqp-network-auth-type'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-network-auth-type/{anqp-network-auth-type}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-network-auth-type/{anqp-network-auth-type}'
            ],
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
            'mkey': 'name'
        },
        'hotspot20_anqproamingconsortium': {
            'params': [
                'adom',
                'anqp-roaming-consortium'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-roaming-consortium/{anqp-roaming-consortium}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-roaming-consortium/{anqp-roaming-consortium}'
            ],
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
            'mkey': 'name'
        },
        'hotspot20_anqproamingconsortium_oilist': {
            'params': [
                'adom',
                'anqp-roaming-consortium',
                'oi-list'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-roaming-consortium/{anqp-roaming-consortium}/oi-list/{oi-list}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-roaming-consortium/{anqp-roaming-consortium}/oi-list/{oi-list}'
            ],
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
            'mkey': 'index'
        },
        'hotspot20_anqpvenuename': {
            'params': [
                'adom',
                'anqp-venue-name'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-venue-name/{anqp-venue-name}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-venue-name/{anqp-venue-name}'
            ],
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
            'mkey': 'name'
        },
        'hotspot20_anqpvenuename_valuelist': {
            'params': [
                'adom',
                'anqp-venue-name',
                'value-list'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-venue-name/{anqp-venue-name}/value-list/{value-list}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-venue-name/{anqp-venue-name}/value-list/{value-list}'
            ],
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
            'mkey': 'index'
        },
        'hotspot20_anqpvenueurl': {
            'params': [
                'anqp-venue-url',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-venue-url/{anqp-venue-url}',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-venue-url/{anqp-venue-url}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'hotspot20_anqpvenueurl_valuelist': {
            'params': [
                'anqp-venue-url',
                'value-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-venue-url/{anqp-venue-url}/value-list/{value-list}',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-venue-url/{anqp-venue-url}/value-list/{value-list}'
            ],
            'revision': {
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
            'mkey': None
        },
        'hotspot20_h2qpadviceofcharge': {
            'params': [
                'h2qp-advice-of-charge',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'hotspot20_h2qpadviceofcharge_aoclist': {
            'params': [
                'h2qp-advice-of-charge',
                'aoc-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}/aoc-list/{aoc-list}',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}/aoc-list/{aoc-list}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'hotspot20_h2qpadviceofcharge_aoclist_planinfo': {
            'params': [
                'h2qp-advice-of-charge',
                'aoc-list',
                'plan-info',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}/aoc-list/{aoc-list}/plan-info/{plan-info}',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}/aoc-list/{aoc-list}/plan-info/{plan-info}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'hotspot20_h2qpconncapability': {
            'params': [
                'adom',
                'h2qp-conn-capability'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-conn-capability/{h2qp-conn-capability}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-conn-capability/{h2qp-conn-capability}'
            ],
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
            'mkey': 'name'
        },
        'hotspot20_h2qpoperatorname': {
            'params': [
                'adom',
                'h2qp-operator-name'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-operator-name/{h2qp-operator-name}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-operator-name/{h2qp-operator-name}'
            ],
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
            'mkey': 'name'
        },
        'hotspot20_h2qpoperatorname_valuelist': {
            'params': [
                'adom',
                'h2qp-operator-name',
                'value-list'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-operator-name/{h2qp-operator-name}/value-list/{value-list}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-operator-name/{h2qp-operator-name}/value-list/{value-list}'
            ],
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
            'mkey': 'index'
        },
        'hotspot20_h2qposuprovider': {
            'params': [
                'adom',
                'h2qp-osu-provider'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}'
            ],
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
            'mkey': 'name'
        },
        'hotspot20_h2qposuprovider_friendlyname': {
            'params': [
                'adom',
                'h2qp-osu-provider',
                'friendly-name'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}/friendly-name/{friendly-name}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}/friendly-name/{friendly-name}'
            ],
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
            'mkey': 'index'
        },
        'hotspot20_h2qposuprovider_servicedescription': {
            'params': [
                'adom',
                'h2qp-osu-provider',
                'service-description'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}/service-description/{service-description}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}/service-description/{service-description}'
            ],
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
            'mkey': 'service-id'
        },
        'hotspot20_h2qposuprovidernai': {
            'params': [
                'h2qp-osu-provider-nai',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-osu-provider-nai/{h2qp-osu-provider-nai}',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-osu-provider-nai/{h2qp-osu-provider-nai}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'hotspot20_h2qposuprovidernai_nailist': {
            'params': [
                'h2qp-osu-provider-nai',
                'nai-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-osu-provider-nai/{h2qp-osu-provider-nai}/nai-list/{nai-list}',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-osu-provider-nai/{h2qp-osu-provider-nai}/nai-list/{nai-list}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'hotspot20_h2qptermsandconditions': {
            'params': [
                'h2qp-terms-and-conditions',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-terms-and-conditions/{h2qp-terms-and-conditions}',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-terms-and-conditions/{h2qp-terms-and-conditions}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'hotspot20_h2qpwanmetric': {
            'params': [
                'adom',
                'h2qp-wan-metric'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-wan-metric/{h2qp-wan-metric}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-wan-metric/{h2qp-wan-metric}'
            ],
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
            'mkey': 'name'
        },
        'hotspot20_hsprofile': {
            'params': [
                'adom',
                'hs-profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/hs-profile/{hs-profile}',
                '/pm/config/global/obj/wireless-controller/hotspot20/hs-profile/{hs-profile}'
            ],
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
            'mkey': 'name'
        },
        'hotspot20_icon': {
            'params': [
                'icon',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/hotspot20/icon/{icon}',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/icon/{icon}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'hotspot20_icon_iconlist': {
            'params': [
                'icon',
                'icon-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/hotspot20/icon/{icon}/icon-list/{icon-list}',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/icon/{icon}/icon-list/{icon-list}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'hotspot20_qosmap': {
            'params': [
                'adom',
                'qos-map'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/qos-map/{qos-map}',
                '/pm/config/global/obj/wireless-controller/hotspot20/qos-map/{qos-map}'
            ],
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
            'mkey': 'name'
        },
        'hotspot20_qosmap_dscpexcept': {
            'params': [
                'adom',
                'qos-map',
                'dscp-except'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/qos-map/{qos-map}/dscp-except/{dscp-except}',
                '/pm/config/global/obj/wireless-controller/hotspot20/qos-map/{qos-map}/dscp-except/{dscp-except}'
            ],
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
            'mkey': 'index'
        },
        'hotspot20_qosmap_dscprange': {
            'params': [
                'adom',
                'qos-map',
                'dscp-range'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/qos-map/{qos-map}/dscp-range/{dscp-range}',
                '/pm/config/global/obj/wireless-controller/hotspot20/qos-map/{qos-map}/dscp-range/{dscp-range}'
            ],
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
            'mkey': 'index'
        },
        'icap_profile': {
            'params': [
                'adom',
                'profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/icap/profile/{profile}',
                '/pm/config/global/obj/icap/profile/{profile}'
            ],
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
            'mkey': 'name'
        },
        'icap_profile_icapheaders': {
            'params': [
                'profile',
                'icap-headers',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/icap/profile/{profile}/icap-headers/{icap-headers}',
                '/pm/config/adom/{adom}/obj/icap/profile/{profile}/icap-headers/{icap-headers}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'icap_profile_respmodforwardrules': {
            'params': [
                'profile',
                'respmod-forward-rules',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/icap/profile/{profile}/respmod-forward-rules/{respmod-forward-rules}',
                '/pm/config/adom/{adom}/obj/icap/profile/{profile}/respmod-forward-rules/{respmod-forward-rules}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'icap_profile_respmodforwardrules_headergroup': {
            'params': [
                'profile',
                'respmod-forward-rules',
                'header-group',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/icap/profile/{profile}/respmod-forward-rules/{respmod-forward-rules}/header-group/{header-group}',
                '/pm/config/adom/{adom}/obj/icap/profile/{profile}/respmod-forward-rules/{respmod-forward-rules}/header-group/{header-group}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'icap_server': {
            'params': [
                'adom',
                'server'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/icap/server/{server}',
                '/pm/config/global/obj/icap/server/{server}'
            ],
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
            'mkey': 'name'
        },
        'ips_baseline_sensor': {
            'params': [
                'sensor',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/ips/baseline/sensor/{sensor}',
                '/pm/config/adom/{adom}/obj/ips/baseline/sensor/{sensor}'
            ],
            'revision': {
                '7.0.1': True,
                '7.0.2': True
            },
            'mkey': 'name'
        },
        'ips_baseline_sensor_entries': {
            'params': [
                'sensor',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/ips/baseline/sensor/{sensor}/entries/{entries}',
                '/pm/config/adom/{adom}/obj/ips/baseline/sensor/{sensor}/entries/{entries}'
            ],
            'revision': {
                '7.0.1': True,
                '7.0.2': True
            },
            'mkey': 'id'
        },
        'ips_baseline_sensor_entries_exemptip': {
            'params': [
                'sensor',
                'entries',
                'exempt-ip',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/ips/baseline/sensor/{sensor}/entries/{entries}/exempt-ip/{exempt-ip}',
                '/pm/config/adom/{adom}/obj/ips/baseline/sensor/{sensor}/entries/{entries}/exempt-ip/{exempt-ip}'
            ],
            'revision': {
                '7.0.1': True,
                '7.0.2': True
            },
            'mkey': 'id'
        },
        'ips_baseline_sensor_filter': {
            'params': [
                'sensor',
                'filter',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/ips/baseline/sensor/{sensor}/filter/{filter}',
                '/pm/config/adom/{adom}/obj/ips/baseline/sensor/{sensor}/filter/{filter}'
            ],
            'revision': {
                '7.0.1': True,
                '7.0.2': True
            },
            'mkey': 'name'
        },
        'ips_baseline_sensor_override': {
            'params': [
                'sensor',
                'override',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/ips/baseline/sensor/{sensor}/override/{override}',
                '/pm/config/adom/{adom}/obj/ips/baseline/sensor/{sensor}/override/{override}'
            ],
            'revision': {
                '7.0.1': True,
                '7.0.2': True
            },
            'mkey': None
        },
        'ips_baseline_sensor_override_exemptip': {
            'params': [
                'sensor',
                'override',
                'exempt-ip',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/ips/baseline/sensor/{sensor}/override/{override}/exempt-ip/{exempt-ip}',
                '/pm/config/adom/{adom}/obj/ips/baseline/sensor/{sensor}/override/{override}/exempt-ip/{exempt-ip}'
            ],
            'revision': {
                '7.0.1': True,
                '7.0.2': True
            },
            'mkey': 'id'
        },
        'ips_custom': {
            'params': [
                'adom',
                'custom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/custom/{custom}',
                '/pm/config/global/obj/ips/custom/{custom}'
            ],
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
            'mkey': 'tag'
        },
        'ips_sensor': {
            'params': [
                'adom',
                'sensor'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}',
                '/pm/config/global/obj/ips/sensor/{sensor}',
                '/pm/config/global/obj/global/ips/sensor/{sensor}',
                '/pm/config/adom/{adom}/obj/global/ips/sensor/{sensor}'
            ],
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
            'mkey': 'name'
        },
        'ips_sensor_entries': {
            'params': [
                'adom',
                'sensor',
                'entries'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}/entries/{entries}',
                '/pm/config/global/obj/ips/sensor/{sensor}/entries/{entries}',
                '/pm/config/global/obj/global/ips/sensor/{sensor}/entries/{entries}',
                '/pm/config/adom/{adom}/obj/global/ips/sensor/{sensor}/entries/{entries}'
            ],
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
            'mkey': 'id'
        },
        'ips_sensor_entries_exemptip': {
            'params': [
                'adom',
                'sensor',
                'entries',
                'exempt-ip'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}/entries/{entries}/exempt-ip/{exempt-ip}',
                '/pm/config/global/obj/ips/sensor/{sensor}/entries/{entries}/exempt-ip/{exempt-ip}',
                '/pm/config/global/obj/global/ips/sensor/{sensor}/entries/{entries}/exempt-ip/{exempt-ip}',
                '/pm/config/adom/{adom}/obj/global/ips/sensor/{sensor}/entries/{entries}/exempt-ip/{exempt-ip}'
            ],
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
            'mkey': 'id'
        },
        'ips_sensor_filter': {
            'params': [
                'adom',
                'sensor',
                'filter'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}/filter/{filter}',
                '/pm/config/global/obj/ips/sensor/{sensor}/filter/{filter}',
                '/pm/config/global/obj/global/ips/sensor/{sensor}/filter/{filter}',
                '/pm/config/adom/{adom}/obj/global/ips/sensor/{sensor}/filter/{filter}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.0': True
            },
            'mkey': 'name'
        },
        'ips_sensor_override': {
            'params': [
                'adom',
                'sensor',
                'override'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}/override/{override}',
                '/pm/config/global/obj/ips/sensor/{sensor}/override/{override}',
                '/pm/config/global/obj/global/ips/sensor/{sensor}/override/{override}',
                '/pm/config/adom/{adom}/obj/global/ips/sensor/{sensor}/override/{override}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.0': True
            },
            'mkey': 'rule-id'
        },
        'ips_sensor_override_exemptip': {
            'params': [
                'adom',
                'sensor',
                'override',
                'exempt-ip'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}/override/{override}/exempt-ip/{exempt-ip}',
                '/pm/config/global/obj/ips/sensor/{sensor}/override/{override}/exempt-ip/{exempt-ip}',
                '/pm/config/global/obj/global/ips/sensor/{sensor}/override/{override}/exempt-ip/{exempt-ip}',
                '/pm/config/adom/{adom}/obj/global/ips/sensor/{sensor}/override/{override}/exempt-ip/{exempt-ip}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.0': True
            },
            'mkey': 'id'
        },
        'log_customfield': {
            'params': [
                'adom',
                'custom-field'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/log/custom-field/{custom-field}',
                '/pm/config/global/obj/log/custom-field/{custom-field}'
            ],
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
            'mkey': 'id'
        },
        'log_npuserver_servergroup': {
            'params': [
                'server-group',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/log/npu-server/server-group/{server-group}',
                '/pm/config/adom/{adom}/obj/log/npu-server/server-group/{server-group}'
            ],
            'revision': {
                '6.4.7': True,
                '6.4.8': True,
                '6.4.9': True,
                '6.4.10': True,
                '6.4.11': True,
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
            'mkey': None
        },
        'log_npuserver_serverinfo': {
            'params': [
                'server-info',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/log/npu-server/server-info/{server-info}',
                '/pm/config/adom/{adom}/obj/log/npu-server/server-info/{server-info}'
            ],
            'revision': {
                '6.4.7': True,
                '6.4.8': True,
                '6.4.9': True,
                '6.4.10': True,
                '6.4.11': True,
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
            'mkey': 'id'
        },
        'mpskprofile': {
            'params': [
                'mpsk-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/mpsk-profile/{mpsk-profile}',
                '/pm/config/adom/{adom}/obj/wireless-controller/mpsk-profile/{mpsk-profile}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'mpskprofile_mpskgroup': {
            'params': [
                'mpsk-profile',
                'mpsk-group',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group/{mpsk-group}',
                '/pm/config/adom/{adom}/obj/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group/{mpsk-group}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'mpskprofile_mpskgroup_mpskkey': {
            'params': [
                'mpsk-profile',
                'mpsk-group',
                'mpsk-key',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group/{mpsk-group}/mpsk-key/{mpsk-key}',
                '/pm/config/adom/{adom}/obj/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group/{mpsk-group}/mpsk-key/{mpsk-key}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'nacprofile': {
            'params': [
                'nac-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/nac-profile/{nac-profile}',
                '/pm/config/adom/{adom}/obj/wireless-controller/nac-profile/{nac-profile}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'pkg_authentication_rule': {
            'params': [
                'adom',
                'pkg',
                'rule'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/authentication/rule/{rule}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'pkg_central_dnat': {
            'params': [
                'adom',
                'pkg',
                'dnat'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/central/dnat/{dnat}'
            ],
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
            'mkey': 'name'
        },
        'pkg_central_dnat6': {
            'params': [
                'adom',
                'pkg',
                'dnat6'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/central/dnat6/{dnat6}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'pkg_firewall_acl': {
            'params': [
                'adom',
                'pkg',
                'acl'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/acl/{acl}'
            ],
            'revision': {
                '7.2.0': True
            },
            'mkey': 'name'
        },
        'pkg_firewall_acl6': {
            'params': [
                'adom',
                'pkg',
                'acl6'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/acl6/{acl6}'
            ],
            'revision': {
                '7.2.0': True
            },
            'mkey': 'name'
        },
        'pkg_firewall_centralsnatmap': {
            'params': [
                'adom',
                'pkg',
                'central-snat-map'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/central-snat-map/{central-snat-map}'
            ],
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
            'mkey': 'policyid'
        },
        'pkg_firewall_consolidated_policy': {
            'params': [
                'adom',
                'pkg',
                'policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/consolidated/policy/{policy}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'pkg_firewall_dospolicy': {
            'params': [
                'adom',
                'pkg',
                'DoS-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/DoS-policy/{DoS-policy}'
            ],
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
            'mkey': 'policyid'
        },
        'pkg_firewall_dospolicy6': {
            'params': [
                'adom',
                'pkg',
                'DoS-policy6'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/DoS-policy6/{DoS-policy6}'
            ],
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
            'mkey': 'policyid'
        },
        'pkg_firewall_dospolicy6_anomaly': {
            'params': [
                'adom',
                'pkg',
                'DoS-policy6',
                'anomaly'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/DoS-policy6/{DoS-policy6}/anomaly/{anomaly}'
            ],
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
            'mkey': 'name'
        },
        'pkg_firewall_dospolicy_anomaly': {
            'params': [
                'adom',
                'pkg',
                'DoS-policy',
                'anomaly'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/DoS-policy/{DoS-policy}/anomaly/{anomaly}'
            ],
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
            'mkey': 'name'
        },
        'pkg_firewall_explicitproxypolicy': {
            'params': [
                'adom',
                'pkg',
                'explicit-proxy-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/explicit-proxy-policy/{explicit-proxy-policy}'
            ],
            'revision': {
                '6.2.0': True,
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.6': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True
            },
            'mkey': None
        },
        'pkg_firewall_explicitproxypolicy_identitybasedpolicy': {
            'params': [
                'adom',
                'pkg',
                'explicit-proxy-policy',
                'identity-based-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/explicit-proxy-policy/{explicit-proxy-policy}/identity-based-policy/{identity-based-policy}'
            ],
            'revision': {
                '6.2.0': True,
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.6': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True
            },
            'mkey': 'id'
        },
        'pkg_firewall_hyperscalepolicy': {
            'params': [
                'adom',
                'pkg',
                'hyperscale-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/hyperscale-policy/{hyperscale-policy}'
            ],
            'revision': {
                '6.4.7': True,
                '6.4.8': True,
                '6.4.9': True,
                '6.4.10': True,
                '6.4.11': True,
                '7.0.1': True,
                '7.0.2': True,
                '7.0.3': True,
                '7.0.4': True,
                '7.0.5': True,
                '7.0.6': True,
                '7.0.7': True,
                '7.2.0': True
            },
            'mkey': 'name'
        },
        'pkg_firewall_hyperscalepolicy46': {
            'params': [
                'adom',
                'pkg',
                'hyperscale-policy46'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/hyperscale-policy46/{hyperscale-policy46}'
            ],
            'revision': {
                '6.4.7': True,
                '6.4.8': True,
                '6.4.9': True,
                '6.4.10': True,
                '6.4.11': True,
                '7.0.1': True,
                '7.0.2': True,
                '7.0.3': True,
                '7.0.4': True,
                '7.0.5': True,
                '7.0.6': True,
                '7.0.7': True,
                '7.2.0': True
            },
            'mkey': 'name'
        },
        'pkg_firewall_hyperscalepolicy6': {
            'params': [
                'adom',
                'pkg',
                'hyperscale-policy6'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/hyperscale-policy6/{hyperscale-policy6}'
            ],
            'revision': {
                '6.4.7': True,
                '6.4.8': True,
                '6.4.9': True,
                '6.4.10': True,
                '6.4.11': True,
                '7.0.1': True,
                '7.0.2': True,
                '7.0.3': True,
                '7.0.4': True,
                '7.0.5': True,
                '7.0.6': True,
                '7.0.7': True,
                '7.2.0': True
            },
            'mkey': 'name'
        },
        'pkg_firewall_hyperscalepolicy64': {
            'params': [
                'adom',
                'pkg',
                'hyperscale-policy64'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/hyperscale-policy64/{hyperscale-policy64}'
            ],
            'revision': {
                '6.4.7': True,
                '6.4.8': True,
                '6.4.9': True,
                '6.4.10': True,
                '6.4.11': True,
                '7.0.1': True,
                '7.0.2': True,
                '7.0.3': True,
                '7.0.4': True,
                '7.0.5': True,
                '7.0.6': True,
                '7.0.7': True,
                '7.2.0': True
            },
            'mkey': 'name'
        },
        'pkg_firewall_interfacepolicy': {
            'params': [
                'adom',
                'pkg',
                'interface-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/interface-policy/{interface-policy}'
            ],
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
                '7.2.2': True
            },
            'mkey': 'policyid'
        },
        'pkg_firewall_interfacepolicy6': {
            'params': [
                'adom',
                'pkg',
                'interface-policy6'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/interface-policy6/{interface-policy6}'
            ],
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
                '7.2.2': True
            },
            'mkey': 'policyid'
        },
        'pkg_firewall_localinpolicy': {
            'params': [
                'adom',
                'pkg',
                'local-in-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/local-in-policy/{local-in-policy}'
            ],
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
            'mkey': 'policyid'
        },
        'pkg_firewall_localinpolicy6': {
            'params': [
                'adom',
                'pkg',
                'local-in-policy6'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/local-in-policy6/{local-in-policy6}'
            ],
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
            'mkey': 'policyid'
        },
        'pkg_firewall_multicastpolicy': {
            'params': [
                'adom',
                'pkg',
                'multicast-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/multicast-policy/{multicast-policy}'
            ],
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
            'mkey': 'id'
        },
        'pkg_firewall_multicastpolicy6': {
            'params': [
                'adom',
                'pkg',
                'multicast-policy6'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/multicast-policy6/{multicast-policy6}'
            ],
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
            'mkey': 'id'
        },
        'pkg_firewall_policy': {
            'params': [
                'adom',
                'pkg',
                'policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policy}'
            ],
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
            'mkey': 'policyid'
        },
        'pkg_firewall_policy46': {
            'params': [
                'adom',
                'pkg',
                'policy46'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy46/{policy46}'
            ],
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
            'mkey': 'policyid'
        },
        'pkg_firewall_policy6': {
            'params': [
                'adom',
                'pkg',
                'policy6'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy6/{policy6}'
            ],
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
            'mkey': 'policyid'
        },
        'pkg_firewall_policy64': {
            'params': [
                'adom',
                'pkg',
                'policy64'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy64/{policy64}'
            ],
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
            'mkey': 'policyid'
        },
        'pkg_firewall_policy_vpndstnode': {
            'params': [
                'adom',
                'pkg',
                'policy',
                'vpn_dst_node'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policy}/vpn_dst_node/{vpn_dst_node}'
            ],
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
                '7.0.2': True
            },
            'mkey': 'seq'
        },
        'pkg_firewall_policy_vpnsrcnode': {
            'params': [
                'adom',
                'pkg',
                'policy',
                'vpn_src_node'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policy}/vpn_src_node/{vpn_src_node}'
            ],
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
                '7.0.2': True
            },
            'mkey': 'seq'
        },
        'pkg_firewall_proxypolicy': {
            'params': [
                'adom',
                'pkg',
                'proxy-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/proxy-policy/{proxy-policy}'
            ],
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
            'mkey': 'policyid'
        },
        'pkg_firewall_securitypolicy': {
            'params': [
                'adom',
                'pkg',
                'security-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/security-policy/{security-policy}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'pkg_firewall_shapingpolicy': {
            'params': [
                'adom',
                'pkg',
                'shaping-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/shaping-policy/{shaping-policy}'
            ],
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
            'mkey': 'id'
        },
        'pkg_footer_consolidated_policy': {
            'params': [
                'pkg',
                'policy',
                'adom'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/footer/consolidated/policy/{policy}',
                '/pm/config/adom/{adom}/pkg/{pkg}/global/footer/consolidated/policy/{policy}'
            ],
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
            'mkey': 'name'
        },
        'pkg_footer_policy': {
            'params': [
                'pkg',
                'policy',
                'adom'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/footer/policy/{policy}',
                '/pm/config/adom/{adom}/pkg/{pkg}/global/footer/policy/{policy}'
            ],
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
            'mkey': 'policyid'
        },
        'pkg_footer_policy6': {
            'params': [
                'pkg',
                'policy6',
                'adom'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/footer/policy6/{policy6}',
                '/pm/config/adom/{adom}/pkg/{pkg}/global/footer/policy6/{policy6}'
            ],
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
            'mkey': 'policyid'
        },
        'pkg_footer_policy6_identitybasedpolicy6': {
            'params': [
                'pkg',
                'policy6',
                'identity-based-policy6'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/footer/policy6/{policy6}/identity-based-policy6/{identity-based-policy6}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.0': True
            },
            'mkey': 'id'
        },
        'pkg_footer_policy_identitybasedpolicy': {
            'params': [
                'pkg',
                'policy',
                'identity-based-policy'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/footer/policy/{policy}/identity-based-policy/{identity-based-policy}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.0': True
            },
            'mkey': 'id'
        },
        'pkg_footer_shapingpolicy': {
            'params': [
                'pkg',
                'shaping-policy',
                'adom'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/footer/shaping-policy/{shaping-policy}',
                '/pm/config/adom/{adom}/pkg/{pkg}/global/footer/shaping-policy/{shaping-policy}'
            ],
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
            'mkey': 'id'
        },
        'pkg_header_consolidated_policy': {
            'params': [
                'pkg',
                'policy',
                'adom'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/header/consolidated/policy/{policy}',
                '/pm/config/adom/{adom}/pkg/{pkg}/global/header/consolidated/policy/{policy}'
            ],
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
            'mkey': 'name'
        },
        'pkg_header_policy': {
            'params': [
                'pkg',
                'policy',
                'adom'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/header/policy/{policy}',
                '/pm/config/adom/{adom}/pkg/{pkg}/global/header/policy/{policy}'
            ],
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
            'mkey': 'policyid'
        },
        'pkg_header_policy6': {
            'params': [
                'pkg',
                'policy6',
                'adom'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/header/policy6/{policy6}',
                '/pm/config/adom/{adom}/pkg/{pkg}/global/header/policy6/{policy6}'
            ],
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
            'mkey': 'policyid'
        },
        'pkg_header_policy6_identitybasedpolicy6': {
            'params': [
                'pkg',
                'policy6',
                'identity-based-policy6'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/header/policy6/{policy6}/identity-based-policy6/{identity-based-policy6}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.0': True
            },
            'mkey': 'id'
        },
        'pkg_header_policy_identitybasedpolicy': {
            'params': [
                'pkg',
                'policy',
                'identity-based-policy'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/header/policy/{policy}/identity-based-policy/{identity-based-policy}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.0': True
            },
            'mkey': 'id'
        },
        'pkg_header_shapingpolicy': {
            'params': [
                'pkg',
                'shaping-policy',
                'adom'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/header/shaping-policy/{shaping-policy}',
                '/pm/config/adom/{adom}/pkg/{pkg}/global/header/shaping-policy/{shaping-policy}'
            ],
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
            'mkey': 'id'
        },
        'pkg_user_nacpolicy': {
            'params': [
                'adom',
                'pkg',
                'nac-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/user/nac-policy/{nac-policy}'
            ],
            'revision': {
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'name'
        },
        'pm_config_pblock_firewall_consolidated_policy': {
            'params': [
                'adom',
                'pblock',
                'policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pblock/{pblock}/firewall/consolidated/policy/{policy}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'pm_config_pblock_firewall_policy': {
            'params': [
                'adom',
                'pblock',
                'policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pblock/{pblock}/firewall/policy/{policy}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'pm_config_pblock_firewall_policy6': {
            'params': [
                'adom',
                'pblock',
                'policy6'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pblock/{pblock}/firewall/policy6/{policy6}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'pm_config_pblock_firewall_securitypolicy': {
            'params': [
                'adom',
                'pblock',
                'security-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pblock/{pblock}/firewall/security-policy/{security-policy}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'qosprofile': {
            'params': [
                'adom',
                'qos-profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/qos-profile/{qos-profile}',
                '/pm/config/global/obj/wireless-controller/qos-profile/{qos-profile}'
            ],
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
            'mkey': 'name'
        },
        'region': {
            'params': [
                'region',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/region/{region}',
                '/pm/config/adom/{adom}/obj/wireless-controller/region/{region}'
            ],
            'revision': {
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True,
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
            'mkey': 'name'
        },
        'router_accesslist': {
            'params': [
                'access-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/router/access-list/{access-list}',
                '/pm/config/adom/{adom}/obj/router/access-list/{access-list}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'router_accesslist6': {
            'params': [
                'access-list6',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/router/access-list6/{access-list6}',
                '/pm/config/adom/{adom}/obj/router/access-list6/{access-list6}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'router_accesslist6_rule': {
            'params': [
                'access-list6',
                'rule',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/router/access-list6/{access-list6}/rule/{rule}',
                '/pm/config/adom/{adom}/obj/router/access-list6/{access-list6}/rule/{rule}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'router_accesslist_rule': {
            'params': [
                'access-list',
                'rule',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/router/access-list/{access-list}/rule/{rule}',
                '/pm/config/adom/{adom}/obj/router/access-list/{access-list}/rule/{rule}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'router_aspathlist': {
            'params': [
                'aspath-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/router/aspath-list/{aspath-list}',
                '/pm/config/adom/{adom}/obj/router/aspath-list/{aspath-list}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'router_aspathlist_rule': {
            'params': [
                'aspath-list',
                'rule',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/router/aspath-list/{aspath-list}/rule/{rule}',
                '/pm/config/adom/{adom}/obj/router/aspath-list/{aspath-list}/rule/{rule}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'router_communitylist': {
            'params': [
                'community-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/router/community-list/{community-list}',
                '/pm/config/adom/{adom}/obj/router/community-list/{community-list}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'router_communitylist_rule': {
            'params': [
                'community-list',
                'rule',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/router/community-list/{community-list}/rule/{rule}',
                '/pm/config/adom/{adom}/obj/router/community-list/{community-list}/rule/{rule}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'router_prefixlist': {
            'params': [
                'prefix-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/router/prefix-list/{prefix-list}',
                '/pm/config/adom/{adom}/obj/router/prefix-list/{prefix-list}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'router_prefixlist6': {
            'params': [
                'prefix-list6',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/router/prefix-list6/{prefix-list6}',
                '/pm/config/adom/{adom}/obj/router/prefix-list6/{prefix-list6}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'router_prefixlist6_rule': {
            'params': [
                'prefix-list6',
                'rule',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/router/prefix-list6/{prefix-list6}/rule/{rule}',
                '/pm/config/adom/{adom}/obj/router/prefix-list6/{prefix-list6}/rule/{rule}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'router_prefixlist_rule': {
            'params': [
                'prefix-list',
                'rule',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/router/prefix-list/{prefix-list}/rule/{rule}',
                '/pm/config/adom/{adom}/obj/router/prefix-list/{prefix-list}/rule/{rule}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'router_routemap': {
            'params': [
                'route-map',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/router/route-map/{route-map}',
                '/pm/config/adom/{adom}/obj/router/route-map/{route-map}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'router_routemap_rule': {
            'params': [
                'route-map',
                'rule',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/router/route-map/{route-map}/rule/{rule}',
                '/pm/config/adom/{adom}/obj/router/route-map/{route-map}/rule/{rule}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'spamfilter_bwl': {
            'params': [
                'adom',
                'bwl'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/bwl/{bwl}',
                '/pm/config/global/obj/spamfilter/bwl/{bwl}'
            ],
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
                '7.2.1': True
            },
            'mkey': 'id'
        },
        'spamfilter_bwl_entries': {
            'params': [
                'adom',
                'bwl',
                'entries'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/bwl/{bwl}/entries/{entries}',
                '/pm/config/global/obj/spamfilter/bwl/{bwl}/entries/{entries}'
            ],
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
                '7.2.1': True
            },
            'mkey': 'id'
        },
        'spamfilter_bword': {
            'params': [
                'adom',
                'bword'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/bword/{bword}',
                '/pm/config/global/obj/spamfilter/bword/{bword}'
            ],
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
                '7.2.1': True
            },
            'mkey': 'id'
        },
        'spamfilter_bword_entries': {
            'params': [
                'adom',
                'bword',
                'entries'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/bword/{bword}/entries/{entries}',
                '/pm/config/global/obj/spamfilter/bword/{bword}/entries/{entries}'
            ],
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
                '7.2.1': True
            },
            'mkey': 'id'
        },
        'spamfilter_dnsbl': {
            'params': [
                'adom',
                'dnsbl'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/dnsbl/{dnsbl}',
                '/pm/config/global/obj/spamfilter/dnsbl/{dnsbl}'
            ],
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
                '7.2.1': True
            },
            'mkey': 'id'
        },
        'spamfilter_dnsbl_entries': {
            'params': [
                'adom',
                'dnsbl',
                'entries'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/dnsbl/{dnsbl}/entries/{entries}',
                '/pm/config/global/obj/spamfilter/dnsbl/{dnsbl}/entries/{entries}'
            ],
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
                '7.2.1': True
            },
            'mkey': 'id'
        },
        'spamfilter_iptrust': {
            'params': [
                'adom',
                'iptrust'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/iptrust/{iptrust}',
                '/pm/config/global/obj/spamfilter/iptrust/{iptrust}'
            ],
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
                '7.2.1': True
            },
            'mkey': 'id'
        },
        'spamfilter_iptrust_entries': {
            'params': [
                'adom',
                'iptrust',
                'entries'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/iptrust/{iptrust}/entries/{entries}',
                '/pm/config/global/obj/spamfilter/iptrust/{iptrust}/entries/{entries}'
            ],
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
                '7.2.1': True
            },
            'mkey': 'id'
        },
        'spamfilter_mheader': {
            'params': [
                'adom',
                'mheader'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/mheader/{mheader}',
                '/pm/config/global/obj/spamfilter/mheader/{mheader}'
            ],
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
                '7.2.1': True
            },
            'mkey': 'id'
        },
        'spamfilter_mheader_entries': {
            'params': [
                'adom',
                'mheader',
                'entries'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/mheader/{mheader}/entries/{entries}',
                '/pm/config/global/obj/spamfilter/mheader/{mheader}/entries/{entries}'
            ],
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
                '7.2.1': True
            },
            'mkey': 'id'
        },
        'spamfilter_profile': {
            'params': [
                'adom',
                'profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/profile/{profile}',
                '/pm/config/global/obj/spamfilter/profile/{profile}'
            ],
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
                '7.2.1': True
            },
            'mkey': 'name'
        },
        'sshfilter_profile': {
            'params': [
                'adom',
                'profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/ssh-filter/profile/{profile}',
                '/pm/config/global/obj/ssh-filter/profile/{profile}'
            ],
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
            'mkey': 'name'
        },
        'sshfilter_profile_filefilter_entries': {
            'params': [
                'profile',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/ssh-filter/profile/{profile}/file-filter/entries/{entries}',
                '/pm/config/adom/{adom}/obj/ssh-filter/profile/{profile}/file-filter/entries/{entries}'
            ],
            'revision': {
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
            'mkey': None
        },
        'sshfilter_profile_shellcommands': {
            'params': [
                'adom',
                'profile',
                'shell-commands'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/ssh-filter/profile/{profile}/shell-commands/{shell-commands}',
                '/pm/config/global/obj/ssh-filter/profile/{profile}/shell-commands/{shell-commands}'
            ],
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
            'mkey': 'id'
        },
        'switchcontroller_acl_group': {
            'params': [
                'group',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/switch-controller/acl/group/{group}',
                '/pm/config/adom/{adom}/obj/switch-controller/acl/group/{group}'
            ],
            'revision': {
                '7.4.0': True
            },
            'mkey': 'name'
        },
        'switchcontroller_acl_ingress': {
            'params': [
                'ingress',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/switch-controller/acl/ingress/{ingress}',
                '/pm/config/adom/{adom}/obj/switch-controller/acl/ingress/{ingress}'
            ],
            'revision': {
                '7.4.0': True
            },
            'mkey': 'id'
        },
        'switchcontroller_customcommand': {
            'params': [
                'custom-command',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/switch-controller/custom-command/{custom-command}',
                '/pm/config/adom/{adom}/obj/switch-controller/custom-command/{custom-command}'
            ],
            'revision': {
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
            'mkey': None
        },
        'switchcontroller_dsl_policy': {
            'params': [
                'policy',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/switch-controller/dsl/policy/{policy}',
                '/pm/config/adom/{adom}/obj/switch-controller/dsl/policy/{policy}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'switchcontroller_dynamicportpolicy': {
            'params': [
                'dynamic-port-policy',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/switch-controller/dynamic-port-policy/{dynamic-port-policy}',
                '/pm/config/adom/{adom}/obj/switch-controller/dynamic-port-policy/{dynamic-port-policy}'
            ],
            'revision': {
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'name'
        },
        'switchcontroller_dynamicportpolicy_policy': {
            'params': [
                'dynamic-port-policy',
                'policy',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/switch-controller/dynamic-port-policy/{dynamic-port-policy}/policy/{policy}',
                '/pm/config/adom/{adom}/obj/switch-controller/dynamic-port-policy/{dynamic-port-policy}/policy/{policy}'
            ],
            'revision': {
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'name'
        },
        'switchcontroller_fortilinksettings': {
            'params': [
                'fortilink-settings',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/switch-controller/fortilink-settings/{fortilink-settings}',
                '/pm/config/adom/{adom}/obj/switch-controller/fortilink-settings/{fortilink-settings}'
            ],
            'revision': {
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'name'
        },
        'switchcontroller_lldpprofile': {
            'params': [
                'adom',
                'lldp-profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/lldp-profile/{lldp-profile}',
                '/pm/config/global/obj/switch-controller/lldp-profile/{lldp-profile}'
            ],
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
            'mkey': 'name'
        },
        'switchcontroller_lldpprofile_customtlvs': {
            'params': [
                'adom',
                'lldp-profile',
                'custom-tlvs'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/lldp-profile/{lldp-profile}/custom-tlvs/{custom-tlvs}',
                '/pm/config/global/obj/switch-controller/lldp-profile/{lldp-profile}/custom-tlvs/{custom-tlvs}'
            ],
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
            'mkey': 'name'
        },
        'switchcontroller_lldpprofile_medlocationservice': {
            'params': [
                'lldp-profile',
                'med-location-service',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/switch-controller/lldp-profile/{lldp-profile}/med-location-service/{med-location-service}',
                '/pm/config/adom/{adom}/obj/switch-controller/lldp-profile/{lldp-profile}/med-location-service/{med-location-service}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'switchcontroller_lldpprofile_mednetworkpolicy': {
            'params': [
                'adom',
                'lldp-profile',
                'med-network-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/lldp-profile/{lldp-profile}/med-network-policy/{med-network-policy}',
                '/pm/config/global/obj/switch-controller/lldp-profile/{lldp-profile}/med-network-policy/{med-network-policy}'
            ],
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
            'mkey': 'name'
        },
        'switchcontroller_macpolicy': {
            'params': [
                'mac-policy',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/switch-controller/mac-policy/{mac-policy}',
                '/pm/config/adom/{adom}/obj/switch-controller/mac-policy/{mac-policy}'
            ],
            'revision': {
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'name'
        },
        'switchcontroller_managedswitch': {
            'params': [
                'adom',
                'managed-switch'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}'
            ],
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
            'mkey': 'name'
        },
        'switchcontroller_managedswitch_customcommand': {
            'params': [
                'managed-switch',
                'custom-command',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/custom-command/{custom-command}',
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/custom-command/{custom-command}'
            ],
            'revision': {
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
            'mkey': None
        },
        'switchcontroller_managedswitch_dhcpsnoopingstaticclient': {
            'params': [
                'managed-switch',
                'dhcp-snooping-static-client',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/dhcp-snooping-static-client/{dhcp-snooping-static-client}',
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/dhcp-snooping-static-client/{dhcp-snooping-static-client}'
            ],
            'revision': {
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'name'
        },
        'switchcontroller_managedswitch_ipsourceguard': {
            'params': [
                'managed-switch',
                'ip-source-guard',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/ip-source-guard/{ip-source-guard}',
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/ip-source-guard/{ip-source-guard}'
            ],
            'revision': {
                '6.4.0': True,
                '6.4.1': True
            },
            'mkey': None
        },
        'switchcontroller_managedswitch_ipsourceguard_bindingentry': {
            'params': [
                'managed-switch',
                'ip-source-guard',
                'binding-entry',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/ip-source-guard/{ip-source-guard}/binding-entry/{binding-entry}',
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/ip-source-guard/{ip-source-guard}/binding-entry/{binding-entry}'
            ],
            'revision': {
                '6.4.0': True,
                '6.4.1': True
            },
            'mkey': None
        },
        'switchcontroller_managedswitch_mirror': {
            'params': [
                'device',
                'vdom',
                'managed-switch',
                'mirror'
            ],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/mirror/{mirror}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.0': True
            },
            'mkey': None
        },
        'switchcontroller_managedswitch_ports': {
            'params': [
                'adom',
                'managed-switch',
                'ports'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/ports/{ports}',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/ports/{ports}'
            ],
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
            'mkey': 'port-name'
        },
        'switchcontroller_managedswitch_ports_dhcpsnoopoption82override': {
            'params': [
                'managed-switch',
                'ports',
                'dhcp-snoop-option82-override',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/ports/{ports}/dhcp-snoop-option82-override/{dhcp-snoop-option82-override}',
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/ports/{ports}/dhcp-snoop-option82-override/{dhcp-snoop-option82-override}'
            ],
            'revision': {
                '7.4.0': True
            },
            'mkey': None
        },
        'switchcontroller_managedswitch_remotelog': {
            'params': [
                'managed-switch',
                'remote-log',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/remote-log/{remote-log}',
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/remote-log/{remote-log}'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True
            },
            'mkey': 'name'
        },
        'switchcontroller_managedswitch_snmpcommunity': {
            'params': [
                'managed-switch',
                'snmp-community',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/snmp-community/{snmp-community}',
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/snmp-community/{snmp-community}'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True
            },
            'mkey': 'id'
        },
        'switchcontroller_managedswitch_snmpcommunity_hosts': {
            'params': [
                'managed-switch',
                'snmp-community',
                'hosts',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/snmp-community/{snmp-community}/hosts/{hosts}',
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/snmp-community/{snmp-community}/hosts/{hosts}'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True
            },
            'mkey': 'id'
        },
        'switchcontroller_managedswitch_snmpuser': {
            'params': [
                'managed-switch',
                'snmp-user',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/snmp-user/{snmp-user}',
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/snmp-user/{snmp-user}'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True
            },
            'mkey': 'name'
        },
        'switchcontroller_managedswitch_staticmac': {
            'params': [
                'device',
                'vdom',
                'managed-switch',
                'static-mac'
            ],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/static-mac/{static-mac}'
            ],
            'revision': {
                '6.2.0': True
            },
            'mkey': None
        },
        'switchcontroller_managedswitch_stpinstance': {
            'params': [
                'device',
                'vdom',
                'managed-switch',
                'stp-instance'
            ],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/stp-instance/{stp-instance}'
            ],
            'revision': {
                '6.2.0': True
            },
            'mkey': None
        },
        'switchcontroller_qos_dot1pmap': {
            'params': [
                'adom',
                'dot1p-map'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/qos/dot1p-map/{dot1p-map}',
                '/pm/config/global/obj/switch-controller/qos/dot1p-map/{dot1p-map}'
            ],
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
            'mkey': 'name'
        },
        'switchcontroller_qos_ipdscpmap': {
            'params': [
                'adom',
                'ip-dscp-map'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/qos/ip-dscp-map/{ip-dscp-map}',
                '/pm/config/global/obj/switch-controller/qos/ip-dscp-map/{ip-dscp-map}'
            ],
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
            'mkey': 'name'
        },
        'switchcontroller_qos_ipdscpmap_map': {
            'params': [
                'adom',
                'ip-dscp-map',
                'map'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/qos/ip-dscp-map/{ip-dscp-map}/map/{map}',
                '/pm/config/global/obj/switch-controller/qos/ip-dscp-map/{ip-dscp-map}/map/{map}'
            ],
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
            'mkey': 'name'
        },
        'switchcontroller_qos_qospolicy': {
            'params': [
                'adom',
                'qos-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/qos/qos-policy/{qos-policy}',
                '/pm/config/global/obj/switch-controller/qos/qos-policy/{qos-policy}'
            ],
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
            'mkey': 'name'
        },
        'switchcontroller_qos_queuepolicy': {
            'params': [
                'adom',
                'queue-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/qos/queue-policy/{queue-policy}',
                '/pm/config/global/obj/switch-controller/qos/queue-policy/{queue-policy}'
            ],
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
            'mkey': 'name'
        },
        'switchcontroller_qos_queuepolicy_cosqueue': {
            'params': [
                'adom',
                'queue-policy',
                'cos-queue'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/qos/queue-policy/{queue-policy}/cos-queue/{cos-queue}',
                '/pm/config/global/obj/switch-controller/qos/queue-policy/{queue-policy}/cos-queue/{cos-queue}'
            ],
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
            'mkey': 'name'
        },
        'switchcontroller_securitypolicy_8021x': {
            'params': [
                'adom',
                '802-1X'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/security-policy/802-1X/{802-1X}',
                '/pm/config/global/obj/switch-controller/security-policy/802-1X/{802-1X}'
            ],
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
            'mkey': 'name'
        },
        'switchcontroller_securitypolicy_captiveportal': {
            'params': [
                'adom',
                'captive-portal'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/security-policy/captive-portal/{captive-portal}',
                '/pm/config/global/obj/switch-controller/security-policy/captive-portal/{captive-portal}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.0': True,
                '6.2.1': True
            },
            'mkey': 'name'
        },
        'switchcontroller_switchinterfacetag': {
            'params': [
                'switch-interface-tag',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/switch-controller/switch-interface-tag/{switch-interface-tag}',
                '/pm/config/adom/{adom}/obj/switch-controller/switch-interface-tag/{switch-interface-tag}'
            ],
            'revision': {
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'name'
        },
        'switchcontroller_trafficpolicy': {
            'params': [
                'traffic-policy',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/switch-controller/traffic-policy/{traffic-policy}',
                '/pm/config/adom/{adom}/obj/switch-controller/traffic-policy/{traffic-policy}'
            ],
            'revision': {
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'id'
        },
        'switchcontroller_vlanpolicy': {
            'params': [
                'vlan-policy',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/switch-controller/vlan-policy/{vlan-policy}',
                '/pm/config/adom/{adom}/obj/switch-controller/vlan-policy/{vlan-policy}'
            ],
            'revision': {
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'name'
        },
        'system_customlanguage': {
            'params': [
                'adom',
                'custom-language'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/custom-language/{custom-language}',
                '/pm/config/global/obj/system/custom-language/{custom-language}'
            ],
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
            'mkey': 'name'
        },
        'system_dhcp_server': {
            'params': [
                'adom',
                'server'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/dhcp/server/{server}',
                '/pm/config/global/obj/system/dhcp/server/{server}'
            ],
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
            'mkey': 'id'
        },
        'system_dhcp_server_excluderange': {
            'params': [
                'adom',
                'server',
                'exclude-range'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/dhcp/server/{server}/exclude-range/{exclude-range}',
                '/pm/config/global/obj/system/dhcp/server/{server}/exclude-range/{exclude-range}'
            ],
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
            'mkey': 'id'
        },
        'system_dhcp_server_iprange': {
            'params': [
                'adom',
                'server',
                'ip-range'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/dhcp/server/{server}/ip-range/{ip-range}',
                '/pm/config/global/obj/system/dhcp/server/{server}/ip-range/{ip-range}'
            ],
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
            'mkey': 'id'
        },
        'system_dhcp_server_options': {
            'params': [
                'adom',
                'server',
                'options'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/dhcp/server/{server}/options/{options}',
                '/pm/config/global/obj/system/dhcp/server/{server}/options/{options}'
            ],
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
            'mkey': 'id'
        },
        'system_dhcp_server_reservedaddress': {
            'params': [
                'adom',
                'server',
                'reserved-address'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/dhcp/server/{server}/reserved-address/{reserved-address}',
                '/pm/config/global/obj/system/dhcp/server/{server}/reserved-address/{reserved-address}'
            ],
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
            'mkey': 'id'
        },
        'system_externalresource': {
            'params': [
                'adom',
                'external-resource'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/external-resource/{external-resource}',
                '/pm/config/global/obj/system/external-resource/{external-resource}'
            ],
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
            'mkey': 'name'
        },
        'system_geoipcountry': {
            'params': [
                'adom',
                'geoip-country'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/geoip-country/{geoip-country}',
                '/pm/config/global/obj/system/geoip-country/{geoip-country}'
            ],
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
            'mkey': 'id'
        },
        'system_geoipoverride': {
            'params': [
                'adom',
                'geoip-override'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/geoip-override/{geoip-override}',
                '/pm/config/global/obj/system/geoip-override/{geoip-override}'
            ],
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
            'mkey': 'name'
        },
        'system_geoipoverride_ip6range': {
            'params': [
                'geoip-override',
                'ip6-range',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/system/geoip-override/{geoip-override}/ip6-range/{ip6-range}',
                '/pm/config/adom/{adom}/obj/system/geoip-override/{geoip-override}/ip6-range/{ip6-range}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'system_geoipoverride_iprange': {
            'params': [
                'adom',
                'geoip-override',
                'ip-range'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/geoip-override/{geoip-override}/ip-range/{ip-range}',
                '/pm/config/global/obj/system/geoip-override/{geoip-override}/ip-range/{ip-range}'
            ],
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
            'mkey': 'id'
        },
        'system_meta': {
            'params': [
                'adom',
                'meta'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/meta/{meta}',
                '/pm/config/global/obj/system/meta/{meta}'
            ],
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
            'mkey': 'name'
        },
        'system_meta_sysmetafields': {
            'params': [
                'adom',
                'meta',
                'sys_meta_fields'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/meta/{meta}/sys_meta_fields/{sys_meta_fields}',
                '/pm/config/global/obj/system/meta/{meta}/sys_meta_fields/{sys_meta_fields}'
            ],
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
            'mkey': 'name'
        },
        'system_npu_dswdtsprofile': {
            'params': [
                'dsw-dts-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/system/npu/dsw-dts-profile/{dsw-dts-profile}',
                '/pm/config/adom/{adom}/obj/system/npu/dsw-dts-profile/{dsw-dts-profile}'
            ],
            'revision': {
                '6.4.7': True,
                '6.4.8': True,
                '6.4.9': True,
                '6.4.10': True,
                '6.4.11': True,
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
            'mkey': None
        },
        'system_npu_dswqueuedtsprofile': {
            'params': [
                'dsw-queue-dts-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/system/npu/dsw-queue-dts-profile/{dsw-queue-dts-profile}',
                '/pm/config/adom/{adom}/obj/system/npu/dsw-queue-dts-profile/{dsw-queue-dts-profile}'
            ],
            'revision': {
                '6.4.7': True,
                '6.4.8': True,
                '6.4.9': True,
                '6.4.10': True,
                '6.4.11': True,
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
            'mkey': 'name'
        },
        'system_npu_npqueues_ethernettype': {
            'params': [
                'ethernet-type',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/system/npu/np-queues/ethernet-type/{ethernet-type}',
                '/pm/config/adom/{adom}/obj/system/npu/np-queues/ethernet-type/{ethernet-type}'
            ],
            'revision': {
                '6.4.7': True,
                '6.4.8': True,
                '6.4.9': True,
                '6.4.10': True,
                '6.4.11': True,
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
            'mkey': 'name'
        },
        'system_npu_npqueues_ipprotocol': {
            'params': [
                'ip-protocol',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/system/npu/np-queues/ip-protocol/{ip-protocol}',
                '/pm/config/adom/{adom}/obj/system/npu/np-queues/ip-protocol/{ip-protocol}'
            ],
            'revision': {
                '6.4.7': True,
                '6.4.8': True,
                '6.4.9': True,
                '6.4.10': True,
                '6.4.11': True,
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
            'mkey': 'name'
        },
        'system_npu_npqueues_ipservice': {
            'params': [
                'ip-service',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/system/npu/np-queues/ip-service/{ip-service}',
                '/pm/config/adom/{adom}/obj/system/npu/np-queues/ip-service/{ip-service}'
            ],
            'revision': {
                '6.4.7': True,
                '6.4.8': True,
                '6.4.9': True,
                '6.4.10': True,
                '6.4.11': True,
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
            'mkey': 'name'
        },
        'system_npu_npqueues_profile': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/system/npu/np-queues/profile/{profile}',
                '/pm/config/adom/{adom}/obj/system/npu/np-queues/profile/{profile}'
            ],
            'revision': {
                '6.4.7': True,
                '6.4.8': True,
                '6.4.9': True,
                '6.4.10': True,
                '6.4.11': True,
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
            'mkey': 'id'
        },
        'system_npu_npqueues_scheduler': {
            'params': [
                'scheduler',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/system/npu/np-queues/scheduler/{scheduler}',
                '/pm/config/adom/{adom}/obj/system/npu/np-queues/scheduler/{scheduler}'
            ],
            'revision': {
                '6.4.7': True,
                '6.4.8': True,
                '6.4.9': True,
                '6.4.10': True,
                '6.4.11': True,
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
            'mkey': 'name'
        },
        'system_npu_portcpumap': {
            'params': [
                'port-cpu-map',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/system/npu/port-cpu-map/{port-cpu-map}',
                '/pm/config/adom/{adom}/obj/system/npu/port-cpu-map/{port-cpu-map}'
            ],
            'revision': {
                '6.4.7': True,
                '6.4.8': True,
                '6.4.9': True,
                '6.4.10': True,
                '6.4.11': True,
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
            'mkey': None
        },
        'system_npu_portnpumap': {
            'params': [
                'port-npu-map',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/system/npu/port-npu-map/{port-npu-map}',
                '/pm/config/adom/{adom}/obj/system/npu/port-npu-map/{port-npu-map}'
            ],
            'revision': {
                '6.4.7': True,
                '6.4.8': True,
                '6.4.9': True,
                '6.4.10': True,
                '6.4.11': True,
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
            'mkey': None
        },
        'system_npu_tcptimeoutprofile': {
            'params': [
                'tcp-timeout-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/system/npu/tcp-timeout-profile/{tcp-timeout-profile}',
                '/pm/config/adom/{adom}/obj/system/npu/tcp-timeout-profile/{tcp-timeout-profile}'
            ],
            'revision': {
                '6.4.7': True,
                '6.4.8': True,
                '6.4.9': True,
                '6.4.10': True,
                '6.4.11': True,
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
            'mkey': 'id'
        },
        'system_npu_udptimeoutprofile': {
            'params': [
                'udp-timeout-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/system/npu/udp-timeout-profile/{udp-timeout-profile}',
                '/pm/config/adom/{adom}/obj/system/npu/udp-timeout-profile/{udp-timeout-profile}'
            ],
            'revision': {
                '6.4.7': True,
                '6.4.8': True,
                '6.4.9': True,
                '6.4.10': True,
                '6.4.11': True,
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
            'mkey': 'id'
        },
        'system_objecttag': {
            'params': [
                'object-tag',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/system/object-tag/{object-tag}',
                '/pm/config/adom/{adom}/obj/system/object-tag/{object-tag}'
            ],
            'revision': {
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
                '6.4.11': True
            },
            'mkey': 'name'
        },
        'system_objecttagging': {
            'params': [
                'adom',
                'object-tagging'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/object-tagging/{object-tagging}',
                '/pm/config/global/obj/system/object-tagging/{object-tagging}'
            ],
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
            'mkey': 'category'
        },
        'system_replacemsggroup': {
            'params': [
                'adom',
                'replacemsg-group'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}'
            ],
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
            'mkey': 'name'
        },
        'system_replacemsggroup_admin': {
            'params': [
                'adom',
                'replacemsg-group',
                'admin'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/admin/{admin}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/admin/{admin}'
            ],
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
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_alertmail': {
            'params': [
                'adom',
                'replacemsg-group',
                'alertmail'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/alertmail/{alertmail}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/alertmail/{alertmail}'
            ],
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
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_auth': {
            'params': [
                'adom',
                'replacemsg-group',
                'auth'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/auth/{auth}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/auth/{auth}'
            ],
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
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_automation': {
            'params': [
                'replacemsg-group',
                'automation',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/automation/{automation}',
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/automation/{automation}'
            ],
            'revision': {
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
            'mkey': None
        },
        'system_replacemsggroup_custommessage': {
            'params': [
                'adom',
                'replacemsg-group',
                'custom-message'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/custom-message/{custom-message}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/custom-message/{custom-message}'
            ],
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
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_devicedetectionportal': {
            'params': [
                'adom',
                'replacemsg-group',
                'device-detection-portal'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/device-detection-portal/{device-detection-portal}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/device-detection-portal/{device-detection-portal}'
            ],
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
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_ec': {
            'params': [
                'adom',
                'replacemsg-group',
                'ec'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/ec/{ec}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/ec/{ec}'
            ],
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
                '7.2.1': True
            },
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_fortiguardwf': {
            'params': [
                'adom',
                'replacemsg-group',
                'fortiguard-wf'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/fortiguard-wf/{fortiguard-wf}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/fortiguard-wf/{fortiguard-wf}'
            ],
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
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_ftp': {
            'params': [
                'adom',
                'replacemsg-group',
                'ftp'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/ftp/{ftp}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/ftp/{ftp}'
            ],
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
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_http': {
            'params': [
                'adom',
                'replacemsg-group',
                'http'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/http/{http}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/http/{http}'
            ],
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
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_icap': {
            'params': [
                'adom',
                'replacemsg-group',
                'icap'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/icap/{icap}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/icap/{icap}'
            ],
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
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_mail': {
            'params': [
                'adom',
                'replacemsg-group',
                'mail'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mail/{mail}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mail/{mail}'
            ],
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
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_mm1': {
            'params': [
                'adom',
                'replacemsg-group',
                'mm1'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mm1/{mm1}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mm1/{mm1}'
            ],
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
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_mm3': {
            'params': [
                'adom',
                'replacemsg-group',
                'mm3'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mm3/{mm3}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mm3/{mm3}'
            ],
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
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_mm4': {
            'params': [
                'adom',
                'replacemsg-group',
                'mm4'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mm4/{mm4}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mm4/{mm4}'
            ],
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
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_mm7': {
            'params': [
                'adom',
                'replacemsg-group',
                'mm7'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mm7/{mm7}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mm7/{mm7}'
            ],
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
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_mms': {
            'params': [
                'adom',
                'replacemsg-group',
                'mms'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mms/{mms}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mms/{mms}'
            ],
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
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_nacquar': {
            'params': [
                'adom',
                'replacemsg-group',
                'nac-quar'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/nac-quar/{nac-quar}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/nac-quar/{nac-quar}'
            ],
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
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_nntp': {
            'params': [
                'adom',
                'replacemsg-group',
                'nntp'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/nntp/{nntp}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/nntp/{nntp}'
            ],
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
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_spam': {
            'params': [
                'adom',
                'replacemsg-group',
                'spam'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/spam/{spam}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/spam/{spam}'
            ],
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
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_sslvpn': {
            'params': [
                'adom',
                'replacemsg-group',
                'sslvpn'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/sslvpn/{sslvpn}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/sslvpn/{sslvpn}'
            ],
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
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_trafficquota': {
            'params': [
                'adom',
                'replacemsg-group',
                'traffic-quota'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/traffic-quota/{traffic-quota}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/traffic-quota/{traffic-quota}'
            ],
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
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_utm': {
            'params': [
                'adom',
                'replacemsg-group',
                'utm'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/utm/{utm}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/utm/{utm}'
            ],
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
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_webproxy': {
            'params': [
                'adom',
                'replacemsg-group',
                'webproxy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/webproxy/{webproxy}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/webproxy/{webproxy}'
            ],
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
            'mkey': 'msg-type'
        },
        'system_replacemsgimage': {
            'params': [
                'adom',
                'replacemsg-image'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-image/{replacemsg-image}',
                '/pm/config/global/obj/system/replacemsg-image/{replacemsg-image}'
            ],
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
            'mkey': 'name'
        },
        'system_sdnconnector': {
            'params': [
                'adom',
                'sdn-connector'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}'
            ],
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
            'mkey': 'name'
        },
        'system_sdnconnector_compartmentlist': {
            'params': [
                'sdn-connector',
                'compartment-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/compartment-list/{compartment-list}',
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/compartment-list/{compartment-list}'
            ],
            'revision': {
                '7.4.0': True
            },
            'mkey': None
        },
        'system_sdnconnector_externalaccountlist': {
            'params': [
                'sdn-connector',
                'external-account-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/external-account-list/{external-account-list}',
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/external-account-list/{external-account-list}'
            ],
            'revision': {
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
            'mkey': None
        },
        'system_sdnconnector_externalip': {
            'params': [
                'adom',
                'sdn-connector',
                'external-ip'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/external-ip/{external-ip}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/external-ip/{external-ip}'
            ],
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
            'mkey': 'name'
        },
        'system_sdnconnector_forwardingrule': {
            'params': [
                'sdn-connector',
                'forwarding-rule',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/forwarding-rule/{forwarding-rule}',
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/forwarding-rule/{forwarding-rule}'
            ],
            'revision': {
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
            'mkey': None
        },
        'system_sdnconnector_gcpprojectlist': {
            'params': [
                'sdn-connector',
                'gcp-project-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/gcp-project-list/{gcp-project-list}',
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/gcp-project-list/{gcp-project-list}'
            ],
            'revision': {
                '6.4.7': True,
                '6.4.8': True,
                '6.4.9': True,
                '6.4.10': True,
                '6.4.11': True,
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
            'mkey': 'id'
        },
        'system_sdnconnector_nic': {
            'params': [
                'adom',
                'sdn-connector',
                'nic'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/nic/{nic}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/nic/{nic}'
            ],
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
            'mkey': 'name'
        },
        'system_sdnconnector_nic_ip': {
            'params': [
                'adom',
                'sdn-connector',
                'nic',
                'ip'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/nic/{nic}/ip/{ip}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/nic/{nic}/ip/{ip}'
            ],
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
            'mkey': 'name'
        },
        'system_sdnconnector_ociregionlist': {
            'params': [
                'sdn-connector',
                'oci-region-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/oci-region-list/{oci-region-list}',
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/oci-region-list/{oci-region-list}'
            ],
            'revision': {
                '7.4.0': True
            },
            'mkey': None
        },
        'system_sdnconnector_route': {
            'params': [
                'adom',
                'sdn-connector',
                'route'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/route/{route}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/route/{route}'
            ],
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
            'mkey': 'name'
        },
        'system_sdnconnector_routetable': {
            'params': [
                'adom',
                'sdn-connector',
                'route-table'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/route-table/{route-table}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/route-table/{route-table}'
            ],
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
            'mkey': 'name'
        },
        'system_sdnconnector_routetable_route': {
            'params': [
                'adom',
                'sdn-connector',
                'route-table',
                'route'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/route-table/{route-table}/route/{route}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/route-table/{route-table}/route/{route}'
            ],
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
            'mkey': 'name'
        },
        'system_smsserver': {
            'params': [
                'adom',
                'sms-server'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sms-server/{sms-server}',
                '/pm/config/global/obj/system/sms-server/{sms-server}'
            ],
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
            'mkey': 'name'
        },
        'system_virtualwirepair': {
            'params': [
                'adom',
                'virtual-wire-pair'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/virtual-wire-pair/{virtual-wire-pair}',
                '/pm/config/global/obj/system/virtual-wire-pair/{virtual-wire-pair}'
            ],
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
            'mkey': 'name'
        },
        'template': {
            'params': [
                'adom',
                'template'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/cli/template/{template}',
                '/pm/config/global/obj/cli/template/{template}'
            ],
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
            'mkey': 'name'
        },
        'templategroup': {
            'params': [
                'adom',
                'template-group'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/cli/template-group/{template-group}',
                '/pm/config/global/obj/cli/template-group/{template-group}'
            ],
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
            'mkey': 'name'
        },
        'user_adgrp': {
            'params': [
                'adom',
                'adgrp'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/adgrp/{adgrp}',
                '/pm/config/global/obj/user/adgrp/{adgrp}'
            ],
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
            'mkey': 'id'
        },
        'user_certificate': {
            'params': [
                'certificate',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/certificate/{certificate}',
                '/pm/config/adom/{adom}/obj/user/certificate/{certificate}'
            ],
            'revision': {
                '7.4.0': True
            },
            'mkey': 'id'
        },
        'user_clearpass': {
            'params': [
                'clearpass',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/clearpass/{clearpass}',
                '/pm/config/adom/{adom}/obj/user/clearpass/{clearpass}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'user_connector': {
            'params': [
                'connector',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/connector/{connector}',
                '/pm/config/adom/{adom}/obj/user/connector/{connector}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'user_device': {
            'params': [
                'adom',
                'device'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device/{device}',
                '/pm/config/global/obj/user/device/{device}'
            ],
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
            'mkey': 'alias'
        },
        'user_device_dynamicmapping': {
            'params': [
                'adom',
                'device',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device/{device}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/user/device/{device}/dynamic_mapping/{dynamic_mapping}'
            ],
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
            'mkey': '_scope'
        },
        'user_device_tagging': {
            'params': [
                'adom',
                'device',
                'tagging'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device/{device}/tagging/{tagging}',
                '/pm/config/global/obj/user/device/{device}/tagging/{tagging}'
            ],
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
            'mkey': 'name'
        },
        'user_deviceaccesslist': {
            'params': [
                'device-access-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/device-access-list/{device-access-list}',
                '/pm/config/adom/{adom}/obj/user/device-access-list/{device-access-list}'
            ],
            'revision': {
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
                '7.2.1': True
            },
            'mkey': 'name'
        },
        'user_deviceaccesslist_devicelist': {
            'params': [
                'device-access-list',
                'device-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/device-access-list/{device-access-list}/device-list/{device-list}',
                '/pm/config/adom/{adom}/obj/user/device-access-list/{device-access-list}/device-list/{device-list}'
            ],
            'revision': {
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
                '7.2.1': True
            },
            'mkey': 'id'
        },
        'user_devicecategory': {
            'params': [
                'adom',
                'device-category'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device-category/{device-category}',
                '/pm/config/global/obj/user/device-category/{device-category}'
            ],
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
                '7.2.1': True
            },
            'mkey': 'name'
        },
        'user_devicegroup': {
            'params': [
                'adom',
                'device-group'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device-group/{device-group}',
                '/pm/config/global/obj/user/device-group/{device-group}'
            ],
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
                '7.2.1': True
            },
            'mkey': 'name'
        },
        'user_devicegroup_dynamicmapping': {
            'params': [
                'adom',
                'device-group',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device-group/{device-group}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/user/device-group/{device-group}/dynamic_mapping/{dynamic_mapping}'
            ],
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
                '7.2.1': True
            },
            'mkey': '_scope'
        },
        'user_devicegroup_tagging': {
            'params': [
                'adom',
                'device-group',
                'tagging'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device-group/{device-group}/tagging/{tagging}',
                '/pm/config/global/obj/user/device-group/{device-group}/tagging/{tagging}'
            ],
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
                '7.2.1': True
            },
            'mkey': 'name'
        },
        'user_domaincontroller': {
            'params': [
                'domain-controller',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/domain-controller/{domain-controller}',
                '/pm/config/adom/{adom}/obj/user/domain-controller/{domain-controller}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'user_domaincontroller_extraserver': {
            'params': [
                'domain-controller',
                'extra-server',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/domain-controller/{domain-controller}/extra-server/{extra-server}',
                '/pm/config/adom/{adom}/obj/user/domain-controller/{domain-controller}/extra-server/{extra-server}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'user_exchange': {
            'params': [
                'exchange',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/exchange/{exchange}',
                '/pm/config/adom/{adom}/obj/user/exchange/{exchange}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'user_flexvm': {
            'params': [
                'flexvm',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/flexvm/{flexvm}',
                '/pm/config/adom/{adom}/obj/user/flexvm/{flexvm}'
            ],
            'revision': {
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'name'
        },
        'user_fortitoken': {
            'params': [
                'adom',
                'fortitoken'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/fortitoken/{fortitoken}',
                '/pm/config/global/obj/user/fortitoken/{fortitoken}'
            ],
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
            'mkey': 'serial-number'
        },
        'user_fsso': {
            'params': [
                'adom',
                'fsso'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/fsso/{fsso}',
                '/pm/config/global/obj/user/fsso/{fsso}'
            ],
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
            'mkey': 'name'
        },
        'user_fsso_dynamicmapping': {
            'params': [
                'adom',
                'fsso',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/fsso/{fsso}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/user/fsso/{fsso}/dynamic_mapping/{dynamic_mapping}'
            ],
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
            'mkey': '_scope'
        },
        'user_fssopolling': {
            'params': [
                'adom',
                'fsso-polling'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/fsso-polling/{fsso-polling}',
                '/pm/config/global/obj/user/fsso-polling/{fsso-polling}'
            ],
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
            'mkey': 'id'
        },
        'user_fssopolling_adgrp': {
            'params': [
                'adom',
                'fsso-polling',
                'adgrp'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/fsso-polling/{fsso-polling}/adgrp/{adgrp}',
                '/pm/config/global/obj/user/fsso-polling/{fsso-polling}/adgrp/{adgrp}'
            ],
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
            'mkey': 'name'
        },
        'user_group': {
            'params': [
                'adom',
                'group'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/group/{group}',
                '/pm/config/global/obj/user/group/{group}'
            ],
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
            'mkey': 'name'
        },
        'user_group_dynamicmapping': {
            'params': [
                'group',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/adom/{adom}/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'user_group_dynamicmapping_guest': {
            'params': [
                'group',
                'dynamic_mapping',
                'guest',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}/guest/{guest}',
                '/pm/config/adom/{adom}/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}/guest/{guest}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'user_group_dynamicmapping_match': {
            'params': [
                'group',
                'dynamic_mapping',
                'match',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}/match/{match}',
                '/pm/config/adom/{adom}/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}/match/{match}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'user_group_guest': {
            'params': [
                'adom',
                'group',
                'guest'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/group/{group}/guest/{guest}',
                '/pm/config/global/obj/user/group/{group}/guest/{guest}'
            ],
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
            'mkey': 'user-id'
        },
        'user_group_match': {
            'params': [
                'adom',
                'group',
                'match'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/group/{group}/match/{match}',
                '/pm/config/global/obj/user/group/{group}/match/{match}'
            ],
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
            'mkey': 'id'
        },
        'user_json': {
            'params': [
                'json',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/json/{json}',
                '/pm/config/adom/{adom}/obj/user/json/{json}'
            ],
            'revision': {
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'name'
        },
        'user_krbkeytab': {
            'params': [
                'krb-keytab',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/krb-keytab/{krb-keytab}',
                '/pm/config/adom/{adom}/obj/user/krb-keytab/{krb-keytab}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'user_ldap': {
            'params': [
                'adom',
                'ldap'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/ldap/{ldap}',
                '/pm/config/global/obj/user/ldap/{ldap}'
            ],
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
            'mkey': 'name'
        },
        'user_ldap_dynamicmapping': {
            'params': [
                'adom',
                'ldap',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/ldap/{ldap}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/user/ldap/{ldap}/dynamic_mapping/{dynamic_mapping}'
            ],
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
            'mkey': '_scope'
        },
        'user_local': {
            'params': [
                'adom',
                'local'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/local/{local}',
                '/pm/config/global/obj/user/local/{local}'
            ],
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
            'mkey': 'name'
        },
        'user_nsx': {
            'params': [
                'nsx',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/nsx/{nsx}',
                '/pm/config/adom/{adom}/obj/user/nsx/{nsx}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'user_nsx_service': {
            'params': [
                'nsx',
                'service',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/nsx/{nsx}/service/{service}',
                '/pm/config/adom/{adom}/obj/user/nsx/{nsx}/service/{service}'
            ],
            'revision': {
                '7.0.4': True,
                '7.0.5': True,
                '7.0.6': True,
                '7.0.7': True,
                '7.2.0': True,
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'id'
        },
        'user_passwordpolicy': {
            'params': [
                'adom',
                'password-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/password-policy/{password-policy}',
                '/pm/config/global/obj/user/password-policy/{password-policy}'
            ],
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
            'mkey': 'name'
        },
        'user_peer': {
            'params': [
                'adom',
                'peer'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/peer/{peer}',
                '/pm/config/global/obj/user/peer/{peer}'
            ],
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
            'mkey': 'name'
        },
        'user_peergrp': {
            'params': [
                'adom',
                'peergrp'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/peergrp/{peergrp}',
                '/pm/config/global/obj/user/peergrp/{peergrp}'
            ],
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
            'mkey': 'name'
        },
        'user_pop3': {
            'params': [
                'adom',
                'pop3'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/pop3/{pop3}',
                '/pm/config/global/obj/user/pop3/{pop3}'
            ],
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
            'mkey': 'name'
        },
        'user_pxgrid': {
            'params': [
                'adom',
                'pxgrid'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/pxgrid/{pxgrid}',
                '/pm/config/global/obj/user/pxgrid/{pxgrid}'
            ],
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
            'mkey': 'name'
        },
        'user_radius': {
            'params': [
                'adom',
                'radius'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/radius/{radius}',
                '/pm/config/global/obj/user/radius/{radius}'
            ],
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
            'mkey': 'name'
        },
        'user_radius_accountingserver': {
            'params': [
                'adom',
                'radius',
                'accounting-server'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/radius/{radius}/accounting-server/{accounting-server}',
                '/pm/config/global/obj/user/radius/{radius}/accounting-server/{accounting-server}'
            ],
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
            'mkey': 'id'
        },
        'user_radius_dynamicmapping': {
            'params': [
                'adom',
                'radius',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/radius/{radius}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/user/radius/{radius}/dynamic_mapping/{dynamic_mapping}'
            ],
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
            'mkey': '_scope'
        },
        'user_radius_dynamicmapping_accountingserver': {
            'params': [
                'radius',
                'dynamic_mapping',
                'accounting-server',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/radius/{radius}/dynamic_mapping/{dynamic_mapping}/accounting-server/{accounting-server}',
                '/pm/config/adom/{adom}/obj/user/radius/{radius}/dynamic_mapping/{dynamic_mapping}/accounting-server/{accounting-server}'
            ],
            'revision': {
                '6.2.6': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True,
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
            'mkey': 'id'
        },
        'user_saml': {
            'params': [
                'saml',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/saml/{saml}',
                '/pm/config/adom/{adom}/obj/user/saml/{saml}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'user_saml_dynamicmapping': {
            'params': [
                'saml',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/saml/{saml}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/adom/{adom}/obj/user/saml/{saml}/dynamic_mapping/{dynamic_mapping}'
            ],
            'revision': {
                '7.0.5': True,
                '7.0.6': True,
                '7.0.7': True,
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': None
        },
        'user_securityexemptlist': {
            'params': [
                'adom',
                'security-exempt-list'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/security-exempt-list/{security-exempt-list}',
                '/pm/config/global/obj/user/security-exempt-list/{security-exempt-list}'
            ],
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
            'mkey': 'name'
        },
        'user_securityexemptlist_rule': {
            'params': [
                'adom',
                'security-exempt-list',
                'rule'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/security-exempt-list/{security-exempt-list}/rule/{rule}',
                '/pm/config/global/obj/user/security-exempt-list/{security-exempt-list}/rule/{rule}'
            ],
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
            'mkey': 'id'
        },
        'user_tacacs': {
            'params': [
                'adom',
                'tacacs+'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/tacacs+/{tacacs+}',
                '/pm/config/global/obj/user/tacacs+/{tacacs+}'
            ],
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
            'mkey': 'name'
        },
        'user_tacacs_dynamicmapping': {
            'params': [
                'adom',
                'tacacs+',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/tacacs+/{tacacs+}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/user/tacacs+/{tacacs+}/dynamic_mapping/{dynamic_mapping}'
            ],
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
            'mkey': '_scope'
        },
        'user_vcenter': {
            'params': [
                'vcenter',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/vcenter/{vcenter}',
                '/pm/config/adom/{adom}/obj/user/vcenter/{vcenter}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'user_vcenter_rule': {
            'params': [
                'vcenter',
                'rule',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/vcenter/{vcenter}/rule/{rule}',
                '/pm/config/adom/{adom}/obj/user/vcenter/{vcenter}/rule/{rule}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'utmprofile': {
            'params': [
                'utm-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/utm-profile/{utm-profile}',
                '/pm/config/adom/{adom}/obj/wireless-controller/utm-profile/{utm-profile}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'vap': {
            'params': [
                'adom',
                'vap'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}',
                '/pm/config/global/obj/wireless-controller/vap/{vap}'
            ],
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
            'mkey': 'name'
        },
        'vap_dynamicmapping': {
            'params': [
                'adom',
                'vap',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/wireless-controller/vap/{vap}/dynamic_mapping/{dynamic_mapping}'
            ],
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
            'mkey': '_scope'
        },
        'vap_macfilterlist': {
            'params': [
                'adom',
                'vap',
                'mac-filter-list'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/mac-filter-list/{mac-filter-list}',
                '/pm/config/global/obj/wireless-controller/vap/{vap}/mac-filter-list/{mac-filter-list}'
            ],
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
            'mkey': 'id'
        },
        'vap_mpskkey': {
            'params': [
                'adom',
                'vap',
                'mpsk-key'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/mpsk-key/{mpsk-key}',
                '/pm/config/global/obj/wireless-controller/vap/{vap}/mpsk-key/{mpsk-key}'
            ],
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
            'mkey': 'key-name'
        },
        'vap_vlanname': {
            'params': [
                'vap',
                'vlan-name',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/vap/{vap}/vlan-name/{vlan-name}',
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/vlan-name/{vlan-name}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'vap_vlanpool': {
            'params': [
                'adom',
                'vap',
                'vlan-pool'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/vlan-pool/{vlan-pool}',
                '/pm/config/global/obj/wireless-controller/vap/{vap}/vlan-pool/{vlan-pool}'
            ],
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
            'mkey': 'id'
        },
        'vapgroup': {
            'params': [
                'adom',
                'vap-group'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap-group/{vap-group}',
                '/pm/config/global/obj/wireless-controller/vap-group/{vap-group}'
            ],
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
            'mkey': 'name'
        },
        'videofilter_profile': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/videofilter/profile/{profile}',
                '/pm/config/adom/{adom}/obj/videofilter/profile/{profile}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'videofilter_profile_fortiguardcategory_filters': {
            'params': [
                'profile',
                'filters',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/videofilter/profile/{profile}/fortiguard-category/filters/{filters}',
                '/pm/config/adom/{adom}/obj/videofilter/profile/{profile}/fortiguard-category/filters/{filters}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'videofilter_youtubechannelfilter': {
            'params': [
                'youtube-channel-filter',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/videofilter/youtube-channel-filter/{youtube-channel-filter}',
                '/pm/config/adom/{adom}/obj/videofilter/youtube-channel-filter/{youtube-channel-filter}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'videofilter_youtubechannelfilter_entries': {
            'params': [
                'youtube-channel-filter',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/videofilter/youtube-channel-filter/{youtube-channel-filter}/entries/{entries}',
                '/pm/config/adom/{adom}/obj/videofilter/youtube-channel-filter/{youtube-channel-filter}/entries/{entries}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'voip_profile': {
            'params': [
                'adom',
                'profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/voip/profile/{profile}',
                '/pm/config/global/obj/voip/profile/{profile}'
            ],
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
            'mkey': 'name'
        },
        'vpn_certificate_ca': {
            'params': [
                'adom',
                'ca'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/certificate/ca/{ca}',
                '/pm/config/global/obj/vpn/certificate/ca/{ca}'
            ],
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
            'mkey': 'name'
        },
        'vpn_certificate_ocspserver': {
            'params': [
                'adom',
                'ocsp-server'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/certificate/ocsp-server/{ocsp-server}',
                '/pm/config/global/obj/vpn/certificate/ocsp-server/{ocsp-server}'
            ],
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
            'mkey': 'name'
        },
        'vpn_certificate_remote': {
            'params': [
                'adom',
                'remote'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/certificate/remote/{remote}',
                '/pm/config/global/obj/vpn/certificate/remote/{remote}'
            ],
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
            'mkey': 'name'
        },
        'vpn_ipsec_fec': {
            'params': [
                'fec',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/vpn/ipsec/fec/{fec}',
                '/pm/config/adom/{adom}/obj/vpn/ipsec/fec/{fec}'
            ],
            'revision': {
                '7.2.0': True,
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'name'
        },
        'vpn_ipsec_fec_mappings': {
            'params': [
                'fec',
                'mappings',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/vpn/ipsec/fec/{fec}/mappings/{mappings}',
                '/pm/config/adom/{adom}/obj/vpn/ipsec/fec/{fec}/mappings/{mappings}'
            ],
            'revision': {
                '7.2.0': True,
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': None
        },
        'vpn_ssl_settings_authenticationrule': {
            'params': [
                'device',
                'vdom',
                'authentication-rule'
            ],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/settings/authentication-rule/{authentication-rule}'
            ],
            'revision': {
                '6.2.6': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True,
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
            'mkey': 'id'
        },
        'vpnmgr_node': {
            'params': [
                'adom',
                'node'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpnmgr/node/{node}',
                '/pm/config/global/obj/vpnmgr/node/{node}'
            ],
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
            'mkey': 'id'
        },
        'vpnmgr_node_iprange': {
            'params': [
                'adom',
                'node',
                'ip-range'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpnmgr/node/{node}/ip-range/{ip-range}',
                '/pm/config/global/obj/vpnmgr/node/{node}/ip-range/{ip-range}'
            ],
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
            'mkey': 'id'
        },
        'vpnmgr_node_ipv4excluderange': {
            'params': [
                'adom',
                'node',
                'ipv4-exclude-range'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpnmgr/node/{node}/ipv4-exclude-range/{ipv4-exclude-range}',
                '/pm/config/global/obj/vpnmgr/node/{node}/ipv4-exclude-range/{ipv4-exclude-range}'
            ],
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
            'mkey': 'id'
        },
        'vpnmgr_node_protectedsubnet': {
            'params': [
                'adom',
                'node',
                'protected_subnet'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpnmgr/node/{node}/protected_subnet/{protected_subnet}',
                '/pm/config/global/obj/vpnmgr/node/{node}/protected_subnet/{protected_subnet}'
            ],
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
            'mkey': 'seq'
        },
        'vpnmgr_node_summaryaddr': {
            'params': [
                'adom',
                'node',
                'summary_addr'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpnmgr/node/{node}/summary_addr/{summary_addr}',
                '/pm/config/global/obj/vpnmgr/node/{node}/summary_addr/{summary_addr}'
            ],
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
            'mkey': 'seq'
        },
        'vpnmgr_vpntable': {
            'params': [
                'adom',
                'vpntable'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpnmgr/vpntable/{vpntable}',
                '/pm/config/global/obj/vpnmgr/vpntable/{vpntable}'
            ],
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
            'mkey': 'name'
        },
        'vpnsslweb_hostchecksoftware': {
            'params': [
                'adom',
                'host-check-software'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/host-check-software/{host-check-software}',
                '/pm/config/global/obj/vpn/ssl/web/host-check-software/{host-check-software}'
            ],
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
            'mkey': 'name'
        },
        'vpnsslweb_hostchecksoftware_checkitemlist': {
            'params': [
                'adom',
                'host-check-software',
                'check-item-list'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/host-check-software/{host-check-software}/check-item-list/{check-item-list}',
                '/pm/config/global/obj/vpn/ssl/web/host-check-software/{host-check-software}/check-item-list/{check-item-list}'
            ],
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
            'mkey': 'id'
        },
        'vpnsslweb_portal': {
            'params': [
                'adom',
                'portal'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}'
            ],
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
            'mkey': 'name'
        },
        'vpnsslweb_portal_bookmarkgroup': {
            'params': [
                'adom',
                'portal',
                'bookmark-group'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}'
            ],
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
            'mkey': 'name'
        },
        'vpnsslweb_portal_bookmarkgroup_bookmarks': {
            'params': [
                'adom',
                'portal',
                'bookmark-group',
                'bookmarks'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}/bookmarks/{bookmarks}',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}/bookmarks/{bookmarks}'
            ],
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
            'mkey': 'name'
        },
        'vpnsslweb_portal_bookmarkgroup_bookmarks_formdata': {
            'params': [
                'adom',
                'portal',
                'bookmark-group',
                'bookmarks',
                'form-data'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}/bookmarks/{bookmarks}/form-data/{form-data}',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}/bookmarks/{bookmarks}/form-data/{form-data}'
            ],
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
            'mkey': 'name'
        },
        'vpnsslweb_portal_landingpage_formdata': {
            'params': [
                'portal',
                'form-data',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/landing-page/form-data/{form-data}',
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/landing-page/form-data/{form-data}'
            ],
            'revision': {
                '7.4.0': True
            },
            'mkey': 'name'
        },
        'vpnsslweb_portal_macaddrcheckrule': {
            'params': [
                'adom',
                'portal',
                'mac-addr-check-rule'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/mac-addr-check-rule/{mac-addr-check-rule}',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/mac-addr-check-rule/{mac-addr-check-rule}'
            ],
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
            'mkey': 'name'
        },
        'vpnsslweb_portal_splitdns': {
            'params': [
                'adom',
                'portal',
                'split-dns'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/split-dns/{split-dns}',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/split-dns/{split-dns}'
            ],
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
            'mkey': 'id'
        },
        'vpnsslweb_realm': {
            'params': [
                'adom',
                'realm'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/realm/{realm}',
                '/pm/config/global/obj/vpn/ssl/web/realm/{realm}'
            ],
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
            'mkey': None
        },
        'vpnsslweb_virtualdesktopapplist': {
            'params': [
                'virtual-desktop-app-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/vpn/ssl/web/virtual-desktop-app-list/{virtual-desktop-app-list}',
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/virtual-desktop-app-list/{virtual-desktop-app-list}'
            ],
            'revision': {
                '6.2.0': True,
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.6': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True
            },
            'mkey': 'name'
        },
        'vpnsslweb_virtualdesktopapplist_apps': {
            'params': [
                'virtual-desktop-app-list',
                'apps',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/vpn/ssl/web/virtual-desktop-app-list/{virtual-desktop-app-list}/apps/{apps}',
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/virtual-desktop-app-list/{virtual-desktop-app-list}/apps/{apps}'
            ],
            'revision': {
                '6.2.0': True,
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.6': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True
            },
            'mkey': 'name'
        },
        'waf_mainclass': {
            'params': [
                'adom',
                'main-class'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/main-class/{main-class}',
                '/pm/config/global/obj/waf/main-class/{main-class}'
            ],
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
            'mkey': 'id'
        },
        'waf_profile': {
            'params': [
                'adom',
                'profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}',
                '/pm/config/global/obj/waf/profile/{profile}'
            ],
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
            'mkey': 'name'
        },
        'waf_profile_constraint_exception': {
            'params': [
                'adom',
                'profile',
                'exception'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint/exception/{exception}',
                '/pm/config/global/obj/waf/profile/{profile}/constraint/exception/{exception}'
            ],
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
            'mkey': 'id'
        },
        'waf_profile_method_methodpolicy': {
            'params': [
                'adom',
                'profile',
                'method-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/method/method-policy/{method-policy}',
                '/pm/config/global/obj/waf/profile/{profile}/method/method-policy/{method-policy}'
            ],
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
            'mkey': 'id'
        },
        'waf_profile_signature_customsignature': {
            'params': [
                'adom',
                'profile',
                'custom-signature'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/signature/custom-signature/{custom-signature}',
                '/pm/config/global/obj/waf/profile/{profile}/signature/custom-signature/{custom-signature}'
            ],
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
            'mkey': 'name'
        },
        'waf_profile_urlaccess': {
            'params': [
                'adom',
                'profile',
                'url-access'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/url-access/{url-access}',
                '/pm/config/global/obj/waf/profile/{profile}/url-access/{url-access}'
            ],
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
            'mkey': 'id'
        },
        'waf_profile_urlaccess_accesspattern': {
            'params': [
                'adom',
                'profile',
                'url-access',
                'access-pattern'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/url-access/{url-access}/access-pattern/{access-pattern}',
                '/pm/config/global/obj/waf/profile/{profile}/url-access/{url-access}/access-pattern/{access-pattern}'
            ],
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
            'mkey': 'id'
        },
        'waf_signature': {
            'params': [
                'adom',
                'signature'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/signature/{signature}',
                '/pm/config/global/obj/waf/signature/{signature}'
            ],
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
            'mkey': 'id'
        },
        'waf_subclass': {
            'params': [
                'adom',
                'sub-class'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/sub-class/{sub-class}',
                '/pm/config/global/obj/waf/sub-class/{sub-class}'
            ],
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
            'mkey': 'id'
        },
        'wagprofile': {
            'params': [
                'wag-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/wag-profile/{wag-profile}',
                '/pm/config/adom/{adom}/obj/wireless-controller/wag-profile/{wag-profile}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'wanopt_authgroup': {
            'params': [
                'adom',
                'auth-group'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wanopt/auth-group/{auth-group}',
                '/pm/config/global/obj/wanopt/auth-group/{auth-group}'
            ],
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
            'mkey': 'name'
        },
        'wanopt_peer': {
            'params': [
                'adom',
                'peer'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wanopt/peer/{peer}',
                '/pm/config/global/obj/wanopt/peer/{peer}'
            ],
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
            'mkey': 'peer-host-id'
        },
        'wanopt_profile': {
            'params': [
                'adom',
                'profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wanopt/profile/{profile}',
                '/pm/config/global/obj/wanopt/profile/{profile}'
            ],
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
            'mkey': 'name'
        },
        'wanprof_system_sdwan_duplication': {
            'params': [
                'adom',
                'wanprof',
                'duplication'
            ],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/duplication/{duplication}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'wanprof_system_sdwan_healthcheck': {
            'params': [
                'adom',
                'wanprof',
                'health-check'
            ],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/health-check/{health-check}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'wanprof_system_sdwan_healthcheck_sla': {
            'params': [
                'adom',
                'wanprof',
                'health-check',
                'sla'
            ],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/health-check/{health-check}/sla/{sla}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'wanprof_system_sdwan_members': {
            'params': [
                'adom',
                'wanprof',
                'members'
            ],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/members/{members}'
            ],
            'revision': {
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
            'mkey': None
        },
        'wanprof_system_sdwan_neighbor': {
            'params': [
                'adom',
                'wanprof',
                'neighbor'
            ],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/neighbor/{neighbor}'
            ],
            'revision': {
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
            'mkey': None
        },
        'wanprof_system_sdwan_service': {
            'params': [
                'adom',
                'wanprof',
                'service'
            ],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/service/{service}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'wanprof_system_sdwan_service_sla': {
            'params': [
                'adom',
                'wanprof',
                'service',
                'sla'
            ],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/service/{service}/sla/{sla}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'wanprof_system_sdwan_zone': {
            'params': [
                'adom',
                'wanprof',
                'zone'
            ],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/zone/{zone}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'wanprof_system_virtualwanlink_healthcheck': {
            'params': [
                'adom',
                'wanprof',
                'health-check'
            ],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/health-check/{health-check}'
            ],
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
            'mkey': 'name'
        },
        'wanprof_system_virtualwanlink_healthcheck_sla': {
            'params': [
                'adom',
                'wanprof',
                'health-check',
                'sla'
            ],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/health-check/{health-check}/sla/{sla}'
            ],
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
            'mkey': 'id'
        },
        'wanprof_system_virtualwanlink_members': {
            'params': [
                'adom',
                'wanprof',
                'members'
            ],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/members/{members}'
            ],
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
            'mkey': 'seq-num'
        },
        'wanprof_system_virtualwanlink_neighbor': {
            'params': [
                'adom',
                'wanprof',
                'neighbor'
            ],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/neighbor/{neighbor}'
            ],
            'revision': {
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
            'mkey': None
        },
        'wanprof_system_virtualwanlink_service': {
            'params': [
                'adom',
                'wanprof',
                'service'
            ],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/service/{service}'
            ],
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
            'mkey': 'id'
        },
        'wanprof_system_virtualwanlink_service_sla': {
            'params': [
                'adom',
                'wanprof',
                'service',
                'sla'
            ],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/service/{service}/sla/{sla}'
            ],
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
            'mkey': 'id'
        },
        'webfilter_categories': {
            'params': [
                'adom',
                'categories'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/categories/{categories}',
                '/pm/config/global/obj/webfilter/categories/{categories}'
            ],
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
            'mkey': 'id'
        },
        'webfilter_content': {
            'params': [
                'adom',
                'content'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/content/{content}',
                '/pm/config/global/obj/webfilter/content/{content}'
            ],
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
            'mkey': 'id'
        },
        'webfilter_content_entries': {
            'params': [
                'adom',
                'content',
                'entries'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/content/{content}/entries/{entries}',
                '/pm/config/global/obj/webfilter/content/{content}/entries/{entries}'
            ],
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
            'mkey': 'name'
        },
        'webfilter_contentheader': {
            'params': [
                'adom',
                'content-header'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/content-header/{content-header}',
                '/pm/config/global/obj/webfilter/content-header/{content-header}'
            ],
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
            'mkey': 'id'
        },
        'webfilter_contentheader_entries': {
            'params': [
                'adom',
                'content-header',
                'entries'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/content-header/{content-header}/entries/{entries}',
                '/pm/config/global/obj/webfilter/content-header/{content-header}/entries/{entries}'
            ],
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
            'mkey': None
        },
        'webfilter_ftgdlocalcat': {
            'params': [
                'adom',
                'ftgd-local-cat'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/ftgd-local-cat/{ftgd-local-cat}',
                '/pm/config/global/obj/webfilter/ftgd-local-cat/{ftgd-local-cat}'
            ],
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
            'mkey': 'id'
        },
        'webfilter_ftgdlocalrating': {
            'params': [
                'adom',
                'ftgd-local-rating'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/ftgd-local-rating/{ftgd-local-rating}',
                '/pm/config/global/obj/webfilter/ftgd-local-rating/{ftgd-local-rating}'
            ],
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
            'mkey': 'rating'
        },
        'webfilter_profile': {
            'params': [
                'adom',
                'profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}',
                '/pm/config/global/obj/webfilter/profile/{profile}'
            ],
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
            'mkey': 'name'
        },
        'webfilter_profile_antiphish_custompatterns': {
            'params': [
                'profile',
                'custom-patterns',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/webfilter/profile/{profile}/antiphish/custom-patterns/{custom-patterns}',
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/antiphish/custom-patterns/{custom-patterns}'
            ],
            'revision': {
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
            'mkey': None
        },
        'webfilter_profile_antiphish_inspectionentries': {
            'params': [
                'profile',
                'inspection-entries',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/webfilter/profile/{profile}/antiphish/inspection-entries/{inspection-entries}',
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/antiphish/inspection-entries/{inspection-entries}'
            ],
            'revision': {
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
            'mkey': 'name'
        },
        'webfilter_profile_filefilter_entries': {
            'params': [
                'profile',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/webfilter/profile/{profile}/file-filter/entries/{entries}',
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/file-filter/entries/{entries}'
            ],
            'revision': {
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
            'mkey': None
        },
        'webfilter_profile_ftgdwf_filters': {
            'params': [
                'adom',
                'profile',
                'filters'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/ftgd-wf/filters/{filters}',
                '/pm/config/global/obj/webfilter/profile/{profile}/ftgd-wf/filters/{filters}'
            ],
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
            'mkey': 'id'
        },
        'webfilter_profile_ftgdwf_quota': {
            'params': [
                'adom',
                'profile',
                'quota'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/ftgd-wf/quota/{quota}',
                '/pm/config/global/obj/webfilter/profile/{profile}/ftgd-wf/quota/{quota}'
            ],
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
            'mkey': 'id'
        },
        'webfilter_profile_youtubechannelfilter': {
            'params': [
                'adom',
                'profile',
                'youtube-channel-filter'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/youtube-channel-filter/{youtube-channel-filter}',
                '/pm/config/global/obj/webfilter/profile/{profile}/youtube-channel-filter/{youtube-channel-filter}'
            ],
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
            'mkey': 'id'
        },
        'webfilter_urlfilter': {
            'params': [
                'adom',
                'urlfilter'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/urlfilter/{urlfilter}',
                '/pm/config/global/obj/webfilter/urlfilter/{urlfilter}'
            ],
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
            'mkey': 'id'
        },
        'webfilter_urlfilter_entries': {
            'params': [
                'adom',
                'urlfilter',
                'entries'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/urlfilter/{urlfilter}/entries/{entries}',
                '/pm/config/global/obj/webfilter/urlfilter/{urlfilter}/entries/{entries}'
            ],
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
            'mkey': 'id'
        },
        'webproxy_forwardserver': {
            'params': [
                'adom',
                'forward-server'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/web-proxy/forward-server/{forward-server}',
                '/pm/config/global/obj/web-proxy/forward-server/{forward-server}'
            ],
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
            'mkey': 'name'
        },
        'webproxy_forwardservergroup': {
            'params': [
                'adom',
                'forward-server-group'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/web-proxy/forward-server-group/{forward-server-group}',
                '/pm/config/global/obj/web-proxy/forward-server-group/{forward-server-group}'
            ],
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
            'mkey': 'name'
        },
        'webproxy_forwardservergroup_serverlist': {
            'params': [
                'adom',
                'forward-server-group',
                'server-list'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/web-proxy/forward-server-group/{forward-server-group}/server-list/{server-list}',
                '/pm/config/global/obj/web-proxy/forward-server-group/{forward-server-group}/server-list/{server-list}'
            ],
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
            'mkey': 'name'
        },
        'webproxy_profile': {
            'params': [
                'adom',
                'profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/web-proxy/profile/{profile}',
                '/pm/config/global/obj/web-proxy/profile/{profile}'
            ],
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
            'mkey': 'name'
        },
        'webproxy_profile_headers': {
            'params': [
                'adom',
                'profile',
                'headers'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/web-proxy/profile/{profile}/headers/{headers}',
                '/pm/config/global/obj/web-proxy/profile/{profile}/headers/{headers}'
            ],
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
            'mkey': 'id'
        },
        'webproxy_wisp': {
            'params': [
                'adom',
                'wisp'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/web-proxy/wisp/{wisp}',
                '/pm/config/global/obj/web-proxy/wisp/{wisp}'
            ],
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
            'mkey': 'name'
        },
        'widsprofile': {
            'params': [
                'adom',
                'wids-profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/wids-profile/{wids-profile}',
                '/pm/config/global/obj/wireless-controller/wids-profile/{wids-profile}'
            ],
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
            'mkey': 'name'
        },
        'wireless_accesscontrollist': {
            'params': [
                'access-control-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/access-control-list/{access-control-list}',
                '/pm/config/adom/{adom}/obj/wireless-controller/access-control-list/{access-control-list}'
            ],
            'revision': {
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'name'
        },
        'wireless_accesscontrollist_layer3ipv4rules': {
            'params': [
                'access-control-list',
                'layer3-ipv4-rules',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/access-control-list/{access-control-list}/layer3-ipv4-rules/{layer3-ipv4-rules}',
                '/pm/config/adom/{adom}/obj/wireless-controller/access-control-list/{access-control-list}/layer3-ipv4-rules/{layer3-ipv4-rules}'
            ],
            'revision': {
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': None
        },
        'wireless_accesscontrollist_layer3ipv6rules': {
            'params': [
                'access-control-list',
                'layer3-ipv6-rules',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/access-control-list/{access-control-list}/layer3-ipv6-rules/{layer3-ipv6-rules}',
                '/pm/config/adom/{adom}/obj/wireless-controller/access-control-list/{access-control-list}/layer3-ipv6-rules/{layer3-ipv6-rules}'
            ],
            'revision': {
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': None
        },
        'wireless_address': {
            'params': [
                'address',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/address/{address}',
                '/pm/config/adom/{adom}/obj/wireless-controller/address/{address}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'wireless_addrgrp': {
            'params': [
                'addrgrp',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/addrgrp/{addrgrp}',
                '/pm/config/adom/{adom}/obj/wireless-controller/addrgrp/{addrgrp}'
            ],
            'revision': {
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
            'mkey': 'id'
        },
        'wireless_ssidpolicy': {
            'params': [
                'ssid-policy',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/ssid-policy/{ssid-policy}',
                '/pm/config/adom/{adom}/obj/wireless-controller/ssid-policy/{ssid-policy}'
            ],
            'revision': {
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'name'
        },
        'wireless_syslogprofile': {
            'params': [
                'syslog-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/syslog-profile/{syslog-profile}',
                '/pm/config/adom/{adom}/obj/wireless-controller/syslog-profile/{syslog-profile}'
            ],
            'revision': {
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'mkey': 'name'
        },
        'wtpprofile': {
            'params': [
                'adom',
                'wtp-profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}',
                '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}'
            ],
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
            'mkey': 'name'
        },
        'wtpprofile_denymaclist': {
            'params': [
                'adom',
                'wtp-profile',
                'deny-mac-list'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/deny-mac-list/{deny-mac-list}',
                '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/deny-mac-list/{deny-mac-list}'
            ],
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
            'mkey': 'id'
        },
        'wtpprofile_splittunnelingacl': {
            'params': [
                'adom',
                'wtp-profile',
                'split-tunneling-acl'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/split-tunneling-acl/{split-tunneling-acl}',
                '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/split-tunneling-acl/{split-tunneling-acl}'
            ],
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
            'mkey': 'id'
        }
    }

    module_arg_spec = {
        'access_token': {
            'type': 'str',
            'required': False,
            'no_log': True
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
        'workspace_locking_adom': {
            'type': 'str',
            'required': False
        },
        'workspace_locking_timeout': {
            'type': 'int',
            'required': False,
            'default': 300
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
        'clone': {
            'required': True,
            'type': 'dict',
            'options': {
                'selector': {
                    'required': True,
                    'type': 'str',
                    'choices': [
                        'antivirus_mmschecksum',
                        'antivirus_mmschecksum_entries',
                        'antivirus_notification',
                        'antivirus_notification_entries',
                        'antivirus_profile',
                        'apcfgprofile',
                        'apcfgprofile_commandlist',
                        'application_casi_profile',
                        'application_casi_profile_entries',
                        'application_categories',
                        'application_custom',
                        'application_group',
                        'application_internetservice_entry',
                        'application_internetservicecustom',
                        'application_internetservicecustom_disableentry',
                        'application_internetservicecustom_disableentry_iprange',
                        'application_internetservicecustom_entry',
                        'application_internetservicecustom_entry_portrange',
                        'application_list',
                        'application_list_defaultnetworkservices',
                        'application_list_entries',
                        'application_list_entries_parameters',
                        'application_list_entries_parameters_members',
                        'arrpprofile',
                        'authentication_scheme',
                        'bleprofile',
                        'bonjourprofile',
                        'bonjourprofile_policylist',
                        'certificate_template',
                        'cifs_domaincontroller',
                        'cifs_profile',
                        'cifs_profile_filefilter_entries',
                        'cifs_profile_serverkeytab',
                        'cloud_orchestaws',
                        'cloud_orchestawsconnector',
                        'cloud_orchestawstemplate_autoscaleexistingvpc',
                        'cloud_orchestawstemplate_autoscalenewvpc',
                        'cloud_orchestawstemplate_autoscaletgwnewvpc',
                        'cloud_orchestration',
                        'credentialstore_domaincontroller',
                        'devprof_log_syslogd_filter_excludelist',
                        'devprof_log_syslogd_filter_excludelist_fields',
                        'devprof_log_syslogd_filter_freestyle',
                        'devprof_log_syslogd_setting_customfieldname',
                        'devprof_system_centralmanagement_serverlist',
                        'devprof_system_ntp_ntpserver',
                        'devprof_system_snmp_community',
                        'devprof_system_snmp_community_hosts',
                        'devprof_system_snmp_community_hosts6',
                        'devprof_system_snmp_user',
                        'dlp_datatype',
                        'dlp_dictionary',
                        'dlp_dictionary_entries',
                        'dlp_filepattern',
                        'dlp_filepattern_entries',
                        'dlp_fpsensitivity',
                        'dlp_profile',
                        'dlp_profile_rule',
                        'dlp_sensitivity',
                        'dlp_sensor',
                        'dlp_sensor_entries',
                        'dlp_sensor_filter',
                        'dnsfilter_domainfilter',
                        'dnsfilter_domainfilter_entries',
                        'dnsfilter_profile',
                        'dnsfilter_profile_dnstranslation',
                        'dnsfilter_profile_ftgddns_filters',
                        'dnsfilter_urlfilter',
                        'dnsfilter_urlfilter_entries',
                        'dvmdb_revision',
                        'dynamic_address',
                        'dynamic_address_dynamicaddrmapping',
                        'dynamic_certificate_local',
                        'dynamic_certificate_local_dynamicmapping',
                        'dynamic_input_interface',
                        'dynamic_input_interface_dynamicmapping',
                        'dynamic_interface',
                        'dynamic_interface_dynamicmapping',
                        'dynamic_interface_platformmapping',
                        'dynamic_ippool',
                        'dynamic_multicast_interface',
                        'dynamic_multicast_interface_dynamicmapping',
                        'dynamic_vip',
                        'dynamic_virtualwanlink_members',
                        'dynamic_virtualwanlink_members_dynamicmapping',
                        'dynamic_virtualwanlink_neighbor',
                        'dynamic_virtualwanlink_neighbor_dynamicmapping',
                        'dynamic_virtualwanlink_server',
                        'dynamic_virtualwanlink_server_dynamicmapping',
                        'dynamic_vpntunnel',
                        'dynamic_vpntunnel_dynamicmapping',
                        'emailfilter_blockallowlist',
                        'emailfilter_blockallowlist_entries',
                        'emailfilter_bwl',
                        'emailfilter_bwl_entries',
                        'emailfilter_bword',
                        'emailfilter_bword_entries',
                        'emailfilter_dnsbl',
                        'emailfilter_dnsbl_entries',
                        'emailfilter_iptrust',
                        'emailfilter_iptrust_entries',
                        'emailfilter_mheader',
                        'emailfilter_mheader_entries',
                        'emailfilter_profile',
                        'emailfilter_profile_filefilter_entries',
                        'endpointcontrol_fctems',
                        'extendercontroller_dataplan',
                        'extendercontroller_extenderprofile',
                        'extendercontroller_extenderprofile_cellular_smsnotification_receiver',
                        'extendercontroller_extenderprofile_lanextension_backhaul',
                        'extendercontroller_simprofile',
                        'extendercontroller_template',
                        'extensioncontroller_dataplan',
                        'extensioncontroller_extenderprofile',
                        'extensioncontroller_extenderprofile_cellular_smsnotification_receiver',
                        'extensioncontroller_extenderprofile_lanextension_backhaul',
                        'filefilter_profile',
                        'filefilter_profile_rules',
                        'firewall_accessproxy',
                        'firewall_accessproxy6',
                        'firewall_accessproxy6_apigateway',
                        'firewall_accessproxy6_apigateway6',
                        'firewall_accessproxy6_apigateway6_realservers',
                        'firewall_accessproxy6_apigateway6_sslciphersuites',
                        'firewall_accessproxy6_apigateway_realservers',
                        'firewall_accessproxy6_apigateway_sslciphersuites',
                        'firewall_accessproxy_apigateway',
                        'firewall_accessproxy_apigateway6',
                        'firewall_accessproxy_apigateway6_realservers',
                        'firewall_accessproxy_apigateway6_sslciphersuites',
                        'firewall_accessproxy_apigateway_realservers',
                        'firewall_accessproxy_apigateway_sslciphersuites',
                        'firewall_accessproxy_realservers',
                        'firewall_accessproxy_serverpubkeyauthsettings_certextension',
                        'firewall_accessproxyvirtualhost',
                        'firewall_address',
                        'firewall_address6',
                        'firewall_address6_dynamicmapping',
                        'firewall_address6_dynamicmapping_subnetsegment',
                        'firewall_address6_list',
                        'firewall_address6_profilelist',
                        'firewall_address6_subnetsegment',
                        'firewall_address6_tagging',
                        'firewall_address6template',
                        'firewall_address6template_subnetsegment',
                        'firewall_address6template_subnetsegment_values',
                        'firewall_address_dynamicmapping',
                        'firewall_address_list',
                        'firewall_address_profilelist',
                        'firewall_address_tagging',
                        'firewall_addrgrp',
                        'firewall_addrgrp6',
                        'firewall_addrgrp6_dynamicmapping',
                        'firewall_addrgrp6_tagging',
                        'firewall_addrgrp_dynamicmapping',
                        'firewall_addrgrp_tagging',
                        'firewall_carrierendpointbwl',
                        'firewall_carrierendpointbwl_entries',
                        'firewall_decryptedtrafficmirror',
                        'firewall_explicitproxyaddress',
                        'firewall_explicitproxyaddress_headergroup',
                        'firewall_explicitproxyaddrgrp',
                        'firewall_gtp',
                        'firewall_gtp_apn',
                        'firewall_gtp_ieremovepolicy',
                        'firewall_gtp_imsi',
                        'firewall_gtp_ippolicy',
                        'firewall_gtp_noippolicy',
                        'firewall_gtp_perapnshaper',
                        'firewall_gtp_policy',
                        'firewall_gtp_policyv2',
                        'firewall_identitybasedroute',
                        'firewall_identitybasedroute_rule',
                        'firewall_internetservice_entry',
                        'firewall_internetserviceaddition',
                        'firewall_internetserviceaddition_entry',
                        'firewall_internetserviceaddition_entry_portrange',
                        'firewall_internetservicecustom',
                        'firewall_internetservicecustom_disableentry',
                        'firewall_internetservicecustom_disableentry_iprange',
                        'firewall_internetservicecustom_entry',
                        'firewall_internetservicecustom_entry_portrange',
                        'firewall_internetservicecustomgroup',
                        'firewall_internetservicegroup',
                        'firewall_internetservicename',
                        'firewall_ippool',
                        'firewall_ippool6',
                        'firewall_ippool6_dynamicmapping',
                        'firewall_ippool_dynamicmapping',
                        'firewall_ippoolgrp',
                        'firewall_ldbmonitor',
                        'firewall_mmsprofile',
                        'firewall_mmsprofile_notifmsisdn',
                        'firewall_multicastaddress',
                        'firewall_multicastaddress6',
                        'firewall_multicastaddress6_tagging',
                        'firewall_multicastaddress_tagging',
                        'firewall_networkservicedynamic',
                        'firewall_profilegroup',
                        'firewall_profileprotocoloptions',
                        'firewall_profileprotocoloptions_cifs_filefilter_entries',
                        'firewall_profileprotocoloptions_cifs_serverkeytab',
                        'firewall_proxyaddress',
                        'firewall_proxyaddress_headergroup',
                        'firewall_proxyaddress_tagging',
                        'firewall_proxyaddrgrp',
                        'firewall_proxyaddrgrp_tagging',
                        'firewall_schedule_group',
                        'firewall_schedule_onetime',
                        'firewall_schedule_recurring',
                        'firewall_service_category',
                        'firewall_service_custom',
                        'firewall_service_group',
                        'firewall_shaper_peripshaper',
                        'firewall_shaper_trafficshaper',
                        'firewall_shapingprofile',
                        'firewall_shapingprofile_shapingentries',
                        'firewall_ssh_localca',
                        'firewall_sslsshprofile',
                        'firewall_sslsshprofile_sslexempt',
                        'firewall_sslsshprofile_sslserver',
                        'firewall_trafficclass',
                        'firewall_vip',
                        'firewall_vip46',
                        'firewall_vip46_dynamicmapping',
                        'firewall_vip46_realservers',
                        'firewall_vip6',
                        'firewall_vip64',
                        'firewall_vip64_dynamicmapping',
                        'firewall_vip64_realservers',
                        'firewall_vip6_dynamicmapping',
                        'firewall_vip6_dynamicmapping_realservers',
                        'firewall_vip6_dynamicmapping_sslciphersuites',
                        'firewall_vip6_realservers',
                        'firewall_vip6_sslciphersuites',
                        'firewall_vip6_sslserverciphersuites',
                        'firewall_vip_dynamicmapping',
                        'firewall_vip_dynamicmapping_realservers',
                        'firewall_vip_dynamicmapping_sslciphersuites',
                        'firewall_vip_realservers',
                        'firewall_vip_sslciphersuites',
                        'firewall_vip_sslserverciphersuites',
                        'firewall_vipgrp',
                        'firewall_vipgrp46',
                        'firewall_vipgrp6',
                        'firewall_vipgrp64',
                        'firewall_vipgrp_dynamicmapping',
                        'firewall_wildcardfqdn_custom',
                        'firewall_wildcardfqdn_group',
                        'fmg_device_blueprint',
                        'fmg_fabric_authorization_template',
                        'fmg_fabric_authorization_template_platforms',
                        'fmg_variable',
                        'fmg_variable_dynamicmapping',
                        'fsp_vlan',
                        'fsp_vlan_dhcpserver_excluderange',
                        'fsp_vlan_dhcpserver_iprange',
                        'fsp_vlan_dhcpserver_options',
                        'fsp_vlan_dhcpserver_reservedaddress',
                        'fsp_vlan_dynamicmapping',
                        'fsp_vlan_dynamicmapping_dhcpserver_excluderange',
                        'fsp_vlan_dynamicmapping_dhcpserver_iprange',
                        'fsp_vlan_dynamicmapping_dhcpserver_options',
                        'fsp_vlan_dynamicmapping_dhcpserver_reservedaddress',
                        'fsp_vlan_dynamicmapping_interface_ipv6_ip6delegatedprefixlist',
                        'fsp_vlan_dynamicmapping_interface_ipv6_ip6extraaddr',
                        'fsp_vlan_dynamicmapping_interface_ipv6_ip6prefixlist',
                        'fsp_vlan_dynamicmapping_interface_ipv6_vrrp6',
                        'fsp_vlan_dynamicmapping_interface_secondaryip',
                        'fsp_vlan_dynamicmapping_interface_vrrp',
                        'fsp_vlan_dynamicmapping_interface_vrrp_proxyarp',
                        'fsp_vlan_interface_ipv6_ip6delegatedprefixlist',
                        'fsp_vlan_interface_ipv6_ip6extraaddr',
                        'fsp_vlan_interface_ipv6_ip6prefixlist',
                        'fsp_vlan_interface_ipv6_vrrp6',
                        'fsp_vlan_interface_secondaryip',
                        'fsp_vlan_interface_vrrp',
                        'fsp_vlan_interface_vrrp_proxyarp',
                        'gtp_apn',
                        'gtp_apngrp',
                        'gtp_iewhitelist',
                        'gtp_iewhitelist_entries',
                        'gtp_messagefilterv0v1',
                        'gtp_messagefilterv2',
                        'gtp_tunnellimit',
                        'hotspot20_anqp3gppcellular',
                        'hotspot20_anqp3gppcellular_mccmnclist',
                        'hotspot20_anqpipaddresstype',
                        'hotspot20_anqpnairealm',
                        'hotspot20_anqpnairealm_nailist',
                        'hotspot20_anqpnairealm_nailist_eapmethod',
                        'hotspot20_anqpnairealm_nailist_eapmethod_authparam',
                        'hotspot20_anqpnetworkauthtype',
                        'hotspot20_anqproamingconsortium',
                        'hotspot20_anqproamingconsortium_oilist',
                        'hotspot20_anqpvenuename',
                        'hotspot20_anqpvenuename_valuelist',
                        'hotspot20_anqpvenueurl',
                        'hotspot20_anqpvenueurl_valuelist',
                        'hotspot20_h2qpadviceofcharge',
                        'hotspot20_h2qpadviceofcharge_aoclist',
                        'hotspot20_h2qpadviceofcharge_aoclist_planinfo',
                        'hotspot20_h2qpconncapability',
                        'hotspot20_h2qpoperatorname',
                        'hotspot20_h2qpoperatorname_valuelist',
                        'hotspot20_h2qposuprovider',
                        'hotspot20_h2qposuprovider_friendlyname',
                        'hotspot20_h2qposuprovider_servicedescription',
                        'hotspot20_h2qposuprovidernai',
                        'hotspot20_h2qposuprovidernai_nailist',
                        'hotspot20_h2qptermsandconditions',
                        'hotspot20_h2qpwanmetric',
                        'hotspot20_hsprofile',
                        'hotspot20_icon',
                        'hotspot20_icon_iconlist',
                        'hotspot20_qosmap',
                        'hotspot20_qosmap_dscpexcept',
                        'hotspot20_qosmap_dscprange',
                        'icap_profile',
                        'icap_profile_icapheaders',
                        'icap_profile_respmodforwardrules',
                        'icap_profile_respmodforwardrules_headergroup',
                        'icap_server',
                        'ips_baseline_sensor',
                        'ips_baseline_sensor_entries',
                        'ips_baseline_sensor_entries_exemptip',
                        'ips_baseline_sensor_filter',
                        'ips_baseline_sensor_override',
                        'ips_baseline_sensor_override_exemptip',
                        'ips_custom',
                        'ips_sensor',
                        'ips_sensor_entries',
                        'ips_sensor_entries_exemptip',
                        'ips_sensor_filter',
                        'ips_sensor_override',
                        'ips_sensor_override_exemptip',
                        'log_customfield',
                        'log_npuserver_servergroup',
                        'log_npuserver_serverinfo',
                        'mpskprofile',
                        'mpskprofile_mpskgroup',
                        'mpskprofile_mpskgroup_mpskkey',
                        'nacprofile',
                        'pkg_authentication_rule',
                        'pkg_central_dnat',
                        'pkg_central_dnat6',
                        'pkg_firewall_acl',
                        'pkg_firewall_acl6',
                        'pkg_firewall_centralsnatmap',
                        'pkg_firewall_consolidated_policy',
                        'pkg_firewall_dospolicy',
                        'pkg_firewall_dospolicy6',
                        'pkg_firewall_dospolicy6_anomaly',
                        'pkg_firewall_dospolicy_anomaly',
                        'pkg_firewall_explicitproxypolicy',
                        'pkg_firewall_explicitproxypolicy_identitybasedpolicy',
                        'pkg_firewall_hyperscalepolicy',
                        'pkg_firewall_hyperscalepolicy46',
                        'pkg_firewall_hyperscalepolicy6',
                        'pkg_firewall_hyperscalepolicy64',
                        'pkg_firewall_interfacepolicy',
                        'pkg_firewall_interfacepolicy6',
                        'pkg_firewall_localinpolicy',
                        'pkg_firewall_localinpolicy6',
                        'pkg_firewall_multicastpolicy',
                        'pkg_firewall_multicastpolicy6',
                        'pkg_firewall_policy',
                        'pkg_firewall_policy46',
                        'pkg_firewall_policy6',
                        'pkg_firewall_policy64',
                        'pkg_firewall_policy_vpndstnode',
                        'pkg_firewall_policy_vpnsrcnode',
                        'pkg_firewall_proxypolicy',
                        'pkg_firewall_securitypolicy',
                        'pkg_firewall_shapingpolicy',
                        'pkg_footer_consolidated_policy',
                        'pkg_footer_policy',
                        'pkg_footer_policy6',
                        'pkg_footer_policy6_identitybasedpolicy6',
                        'pkg_footer_policy_identitybasedpolicy',
                        'pkg_footer_shapingpolicy',
                        'pkg_header_consolidated_policy',
                        'pkg_header_policy',
                        'pkg_header_policy6',
                        'pkg_header_policy6_identitybasedpolicy6',
                        'pkg_header_policy_identitybasedpolicy',
                        'pkg_header_shapingpolicy',
                        'pkg_user_nacpolicy',
                        'pm_config_pblock_firewall_consolidated_policy',
                        'pm_config_pblock_firewall_policy',
                        'pm_config_pblock_firewall_policy6',
                        'pm_config_pblock_firewall_securitypolicy',
                        'qosprofile',
                        'region',
                        'router_accesslist',
                        'router_accesslist6',
                        'router_accesslist6_rule',
                        'router_accesslist_rule',
                        'router_aspathlist',
                        'router_aspathlist_rule',
                        'router_communitylist',
                        'router_communitylist_rule',
                        'router_prefixlist',
                        'router_prefixlist6',
                        'router_prefixlist6_rule',
                        'router_prefixlist_rule',
                        'router_routemap',
                        'router_routemap_rule',
                        'spamfilter_bwl',
                        'spamfilter_bwl_entries',
                        'spamfilter_bword',
                        'spamfilter_bword_entries',
                        'spamfilter_dnsbl',
                        'spamfilter_dnsbl_entries',
                        'spamfilter_iptrust',
                        'spamfilter_iptrust_entries',
                        'spamfilter_mheader',
                        'spamfilter_mheader_entries',
                        'spamfilter_profile',
                        'sshfilter_profile',
                        'sshfilter_profile_filefilter_entries',
                        'sshfilter_profile_shellcommands',
                        'switchcontroller_acl_group',
                        'switchcontroller_acl_ingress',
                        'switchcontroller_customcommand',
                        'switchcontroller_dsl_policy',
                        'switchcontroller_dynamicportpolicy',
                        'switchcontroller_dynamicportpolicy_policy',
                        'switchcontroller_fortilinksettings',
                        'switchcontroller_lldpprofile',
                        'switchcontroller_lldpprofile_customtlvs',
                        'switchcontroller_lldpprofile_medlocationservice',
                        'switchcontroller_lldpprofile_mednetworkpolicy',
                        'switchcontroller_macpolicy',
                        'switchcontroller_managedswitch',
                        'switchcontroller_managedswitch_customcommand',
                        'switchcontroller_managedswitch_dhcpsnoopingstaticclient',
                        'switchcontroller_managedswitch_ipsourceguard',
                        'switchcontroller_managedswitch_ipsourceguard_bindingentry',
                        'switchcontroller_managedswitch_mirror',
                        'switchcontroller_managedswitch_ports',
                        'switchcontroller_managedswitch_ports_dhcpsnoopoption82override',
                        'switchcontroller_managedswitch_remotelog',
                        'switchcontroller_managedswitch_snmpcommunity',
                        'switchcontroller_managedswitch_snmpcommunity_hosts',
                        'switchcontroller_managedswitch_snmpuser',
                        'switchcontroller_managedswitch_staticmac',
                        'switchcontroller_managedswitch_stpinstance',
                        'switchcontroller_qos_dot1pmap',
                        'switchcontroller_qos_ipdscpmap',
                        'switchcontroller_qos_ipdscpmap_map',
                        'switchcontroller_qos_qospolicy',
                        'switchcontroller_qos_queuepolicy',
                        'switchcontroller_qos_queuepolicy_cosqueue',
                        'switchcontroller_securitypolicy_8021x',
                        'switchcontroller_securitypolicy_captiveportal',
                        'switchcontroller_switchinterfacetag',
                        'switchcontroller_trafficpolicy',
                        'switchcontroller_vlanpolicy',
                        'system_customlanguage',
                        'system_dhcp_server',
                        'system_dhcp_server_excluderange',
                        'system_dhcp_server_iprange',
                        'system_dhcp_server_options',
                        'system_dhcp_server_reservedaddress',
                        'system_externalresource',
                        'system_geoipcountry',
                        'system_geoipoverride',
                        'system_geoipoverride_ip6range',
                        'system_geoipoverride_iprange',
                        'system_meta',
                        'system_meta_sysmetafields',
                        'system_npu_dswdtsprofile',
                        'system_npu_dswqueuedtsprofile',
                        'system_npu_npqueues_ethernettype',
                        'system_npu_npqueues_ipprotocol',
                        'system_npu_npqueues_ipservice',
                        'system_npu_npqueues_profile',
                        'system_npu_npqueues_scheduler',
                        'system_npu_portcpumap',
                        'system_npu_portnpumap',
                        'system_npu_tcptimeoutprofile',
                        'system_npu_udptimeoutprofile',
                        'system_objecttag',
                        'system_objecttagging',
                        'system_replacemsggroup',
                        'system_replacemsggroup_admin',
                        'system_replacemsggroup_alertmail',
                        'system_replacemsggroup_auth',
                        'system_replacemsggroup_automation',
                        'system_replacemsggroup_custommessage',
                        'system_replacemsggroup_devicedetectionportal',
                        'system_replacemsggroup_ec',
                        'system_replacemsggroup_fortiguardwf',
                        'system_replacemsggroup_ftp',
                        'system_replacemsggroup_http',
                        'system_replacemsggroup_icap',
                        'system_replacemsggroup_mail',
                        'system_replacemsggroup_mm1',
                        'system_replacemsggroup_mm3',
                        'system_replacemsggroup_mm4',
                        'system_replacemsggroup_mm7',
                        'system_replacemsggroup_mms',
                        'system_replacemsggroup_nacquar',
                        'system_replacemsggroup_nntp',
                        'system_replacemsggroup_spam',
                        'system_replacemsggroup_sslvpn',
                        'system_replacemsggroup_trafficquota',
                        'system_replacemsggroup_utm',
                        'system_replacemsggroup_webproxy',
                        'system_replacemsgimage',
                        'system_sdnconnector',
                        'system_sdnconnector_compartmentlist',
                        'system_sdnconnector_externalaccountlist',
                        'system_sdnconnector_externalip',
                        'system_sdnconnector_forwardingrule',
                        'system_sdnconnector_gcpprojectlist',
                        'system_sdnconnector_nic',
                        'system_sdnconnector_nic_ip',
                        'system_sdnconnector_ociregionlist',
                        'system_sdnconnector_route',
                        'system_sdnconnector_routetable',
                        'system_sdnconnector_routetable_route',
                        'system_smsserver',
                        'system_virtualwirepair',
                        'template',
                        'templategroup',
                        'user_adgrp',
                        'user_certificate',
                        'user_clearpass',
                        'user_connector',
                        'user_device',
                        'user_device_dynamicmapping',
                        'user_device_tagging',
                        'user_deviceaccesslist',
                        'user_deviceaccesslist_devicelist',
                        'user_devicecategory',
                        'user_devicegroup',
                        'user_devicegroup_dynamicmapping',
                        'user_devicegroup_tagging',
                        'user_domaincontroller',
                        'user_domaincontroller_extraserver',
                        'user_exchange',
                        'user_flexvm',
                        'user_fortitoken',
                        'user_fsso',
                        'user_fsso_dynamicmapping',
                        'user_fssopolling',
                        'user_fssopolling_adgrp',
                        'user_group',
                        'user_group_dynamicmapping',
                        'user_group_dynamicmapping_guest',
                        'user_group_dynamicmapping_match',
                        'user_group_guest',
                        'user_group_match',
                        'user_json',
                        'user_krbkeytab',
                        'user_ldap',
                        'user_ldap_dynamicmapping',
                        'user_local',
                        'user_nsx',
                        'user_nsx_service',
                        'user_passwordpolicy',
                        'user_peer',
                        'user_peergrp',
                        'user_pop3',
                        'user_pxgrid',
                        'user_radius',
                        'user_radius_accountingserver',
                        'user_radius_dynamicmapping',
                        'user_radius_dynamicmapping_accountingserver',
                        'user_saml',
                        'user_saml_dynamicmapping',
                        'user_securityexemptlist',
                        'user_securityexemptlist_rule',
                        'user_tacacs',
                        'user_tacacs_dynamicmapping',
                        'user_vcenter',
                        'user_vcenter_rule',
                        'utmprofile',
                        'vap',
                        'vap_dynamicmapping',
                        'vap_macfilterlist',
                        'vap_mpskkey',
                        'vap_vlanname',
                        'vap_vlanpool',
                        'vapgroup',
                        'videofilter_profile',
                        'videofilter_profile_fortiguardcategory_filters',
                        'videofilter_youtubechannelfilter',
                        'videofilter_youtubechannelfilter_entries',
                        'voip_profile',
                        'vpn_certificate_ca',
                        'vpn_certificate_ocspserver',
                        'vpn_certificate_remote',
                        'vpn_ipsec_fec',
                        'vpn_ipsec_fec_mappings',
                        'vpn_ssl_settings_authenticationrule',
                        'vpnmgr_node',
                        'vpnmgr_node_iprange',
                        'vpnmgr_node_ipv4excluderange',
                        'vpnmgr_node_protectedsubnet',
                        'vpnmgr_node_summaryaddr',
                        'vpnmgr_vpntable',
                        'vpnsslweb_hostchecksoftware',
                        'vpnsslweb_hostchecksoftware_checkitemlist',
                        'vpnsslweb_portal',
                        'vpnsslweb_portal_bookmarkgroup',
                        'vpnsslweb_portal_bookmarkgroup_bookmarks',
                        'vpnsslweb_portal_bookmarkgroup_bookmarks_formdata',
                        'vpnsslweb_portal_landingpage_formdata',
                        'vpnsslweb_portal_macaddrcheckrule',
                        'vpnsslweb_portal_splitdns',
                        'vpnsslweb_realm',
                        'vpnsslweb_virtualdesktopapplist',
                        'vpnsslweb_virtualdesktopapplist_apps',
                        'waf_mainclass',
                        'waf_profile',
                        'waf_profile_constraint_exception',
                        'waf_profile_method_methodpolicy',
                        'waf_profile_signature_customsignature',
                        'waf_profile_urlaccess',
                        'waf_profile_urlaccess_accesspattern',
                        'waf_signature',
                        'waf_subclass',
                        'wagprofile',
                        'wanopt_authgroup',
                        'wanopt_peer',
                        'wanopt_profile',
                        'wanprof_system_sdwan_duplication',
                        'wanprof_system_sdwan_healthcheck',
                        'wanprof_system_sdwan_healthcheck_sla',
                        'wanprof_system_sdwan_members',
                        'wanprof_system_sdwan_neighbor',
                        'wanprof_system_sdwan_service',
                        'wanprof_system_sdwan_service_sla',
                        'wanprof_system_sdwan_zone',
                        'wanprof_system_virtualwanlink_healthcheck',
                        'wanprof_system_virtualwanlink_healthcheck_sla',
                        'wanprof_system_virtualwanlink_members',
                        'wanprof_system_virtualwanlink_neighbor',
                        'wanprof_system_virtualwanlink_service',
                        'wanprof_system_virtualwanlink_service_sla',
                        'webfilter_categories',
                        'webfilter_content',
                        'webfilter_content_entries',
                        'webfilter_contentheader',
                        'webfilter_contentheader_entries',
                        'webfilter_ftgdlocalcat',
                        'webfilter_ftgdlocalrating',
                        'webfilter_profile',
                        'webfilter_profile_antiphish_custompatterns',
                        'webfilter_profile_antiphish_inspectionentries',
                        'webfilter_profile_filefilter_entries',
                        'webfilter_profile_ftgdwf_filters',
                        'webfilter_profile_ftgdwf_quota',
                        'webfilter_profile_youtubechannelfilter',
                        'webfilter_urlfilter',
                        'webfilter_urlfilter_entries',
                        'webproxy_forwardserver',
                        'webproxy_forwardservergroup',
                        'webproxy_forwardservergroup_serverlist',
                        'webproxy_profile',
                        'webproxy_profile_headers',
                        'webproxy_wisp',
                        'widsprofile',
                        'wireless_accesscontrollist',
                        'wireless_accesscontrollist_layer3ipv4rules',
                        'wireless_accesscontrollist_layer3ipv6rules',
                        'wireless_address',
                        'wireless_addrgrp',
                        'wireless_ssidpolicy',
                        'wireless_syslogprofile',
                        'wtpprofile',
                        'wtpprofile_denymaclist',
                        'wtpprofile_splittunnelingacl'
                    ]
                },
                'self': {
                    'required': True,
                    'type': 'dict'
                },
                'target': {
                    'required': True,
                    'type': 'dict'
                }
            }
        }
    }
    module = AnsibleModule(argument_spec=module_arg_spec,
                           supports_check_mode=False)
    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('access_token', module.params['access_token'] if 'access_token' in module.params else None)
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        connection.set_option('forticloud_access_token',
                              module.params['forticloud_access_token'] if 'forticloud_access_token' in module.params else None)
        fmgr = NAPIManager(None, None, None, None, module, connection)
        fmgr.process_clone(clone_metadata)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()

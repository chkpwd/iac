=============================
Community Azure Release Notes
=============================

.. contents:: Topics


v2.0.0
======

Release Summary
---------------

This release removes all deprecated content - which is all content in this collection. Please remove all FQCNs mentioning this collection and replace them with the appropriate modules from azure.azcollection.

Removed Features (previously deprecated)
----------------------------------------

- azure_rm_aks_facts, azure_rm_aks_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_aks_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_aksversion_facts, azure_rm_aksversion_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_aksversion_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_applicationsecuritygroup_facts, azure_rm_applicationsecuritygroup_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_applicationsecuritygroup_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_appserviceplan_facts, azure_rm_appserviceplan_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_appserviceplan_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_automationaccount_facts, azure_rm_automationaccount_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_automationaccount_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_autoscale_facts, azure_rm_autoscale_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_autoscale_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_availabilityset_facts, azure_rm_availabilityset_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_availabilityset_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_cdnendpoint_facts, azure_rm_cdnendpoint_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_cdnendpoint_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_cdnprofile_facts, azure_rm_cdnprofile_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_cdnprofile_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_containerinstance_facts, azure_rm_containerinstance_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_containerinstance_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_containerregistry_facts, azure_rm_containerregistry_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_containerregistry_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_cosmosdbaccount_facts, azure_rm_cosmosdbaccount_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_cosmosdbaccount_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_deployment_facts, azure_rm_deployment_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_deployment_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_devtestlab_facts, azure_rm_devtestlab_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_devtestlab_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_devtestlabarmtemplate_facts, azure_rm_devtestlabarmtemplate_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_devtestlabarmtemplate_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_devtestlabartifact_facts, azure_rm_devtestlabartifact_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_devtestlabartifact_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_devtestlabartifactsource_facts, azure_rm_devtestlabartifactsource_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_devtestlabartifactsource_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_devtestlabcustomimage_facts, azure_rm_devtestlabcustomimage_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_devtestlabcustomimage_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_devtestlabenvironment_facts, azure_rm_devtestlabenvironment_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_devtestlabenvironment_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_devtestlabpolicy_facts, azure_rm_devtestlabpolicy_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_devtestlabpolicy_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_devtestlabschedule_facts, azure_rm_devtestlabschedule_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_devtestlabschedule_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_devtestlabvirtualmachine_facts, azure_rm_devtestlabvirtualmachine_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_devtestlabvirtualmachine_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_devtestlabvirtualnetwork_facts, azure_rm_devtestlabvirtualnetwork_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_devtestlabvirtualnetwork_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_dnsrecordset_facts, azure_rm_dnsrecordset_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_dnsrecordset_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_dnszone_facts, azure_rm_dnszone_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_dnszone_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_functionapp_facts, azure_rm_functionapp_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_functionapp_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_hdinsightcluster_facts, azure_rm_hdinsightcluster_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_hdinsightcluster_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_image_facts, azure_rm_image_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_image_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_loadbalancer_facts, azure_rm_loadbalancer_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_loadbalancer_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_lock_facts, azure_rm_lock_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_lock_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_loganalyticsworkspace_facts, azure_rm_loganalyticsworkspace_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_loganalyticsworkspace_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_managed_disk, azure_rm_manageddisk - the deprecated modules have been removed. Use azure.azcollection.azure_rm_manageddisk instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_managed_disk_facts, azure_rm_manageddisk_facts, azure_rm_manageddisk_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_manageddisk_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_mariadbconfiguration_facts, azure_rm_mariadbconfiguration_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_mariadbconfiguration_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_mariadbdatabase_facts, azure_rm_mariadbdatabase_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_mariadbdatabase_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_mariadbfirewallrule_facts, azure_rm_mariadbfirewallrule_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_mariadbfirewallrule_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_mariadbserver_facts, azure_rm_mariadbserver_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_mariadbserver_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_mysqlconfiguration_facts, azure_rm_mysqlconfiguration_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_mysqlconfiguration_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_mysqldatabase_facts, azure_rm_mysqldatabase_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_mysqldatabase_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_mysqlfirewallrule_facts, azure_rm_mysqlfirewallrule_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_mysqlfirewallrule_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_mysqlserver_facts, azure_rm_mysqlserver_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_mysqlserver_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_networkinterface_facts, azure_rm_networkinterface_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_networkinterface_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_postgresqlconfiguration_facts, azure_rm_postgresqlconfiguration_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_postgresqlconfiguration_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_postgresqldatabase_facts, azure_rm_postgresqldatabase_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_postgresqldatabase_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_postgresqlfirewallrule_facts, azure_rm_postgresqlfirewallrule_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_postgresqlfirewallrule_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_postgresqlserver_facts, azure_rm_postgresqlserver_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_postgresqlserver_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_publicipaddress_facts, azure_rm_publicipaddress_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_publicipaddress_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_rediscache_facts, azure_rm_rediscache_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_rediscache_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_resource_facts, azure_rm_resource_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_resource_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_resourcegroup_facts, azure_rm_resourcegroup_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_resourcegroup_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_roleassignment_facts, azure_rm_roleassignment_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_roleassignment_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_roledefinition_facts, azure_rm_roledefinition_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_roledefinition_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_routetable_facts, azure_rm_routetable_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_routetable_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_securitygroup_facts, azure_rm_securitygroup_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_securitygroup_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_servicebus_facts, azure_rm_servicebus_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_servicebus_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_sqldatabase_facts, azure_rm_sqldatabase_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_sqldatabase_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_sqlfirewallrule_facts, azure_rm_sqlfirewallrule_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_sqlfirewallrule_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_sqlserver_facts, azure_rm_sqlserver_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_sqlserver_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_storageaccount_facts, azure_rm_storageaccount_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_storageaccount_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_subnet_facts, azure_rm_subnet_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_subnet_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_trafficmanagerendpoint_facts, azure_rm_trafficmanagerendpoint_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_trafficmanagerendpoint_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_trafficmanagerprofile_facts, azure_rm_trafficmanagerprofile_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_trafficmanagerprofile_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_virtualmachine_extension, azure_rm_virtualmachineextension - the deprecated modules have been removed. Use azure.azcollection.azure_rm_virtualmachineextension instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_virtualmachine_facts, azure_rm_virtualmachine_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_virtualmachine_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_virtualmachine_scaleset, azure_rm_virtualmachinescaleset - the deprecated modules have been removed. Use azure.azcollection.azure_rm_virtualmachinescaleset instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_virtualmachine_scaleset_facts, azure_rm_virtualmachinescaleset_facts, azure_rm_virtualmachinescaleset_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_virtualmachinescaleset_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_virtualmachineextension_facts, azure_rm_virtualmachineextension_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_virtualmachineextension_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_virtualmachineimage_facts, azure_rm_virtualmachineimage_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_virtualmachineimage_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_virtualmachinescalesetextension_facts, azure_rm_virtualmachinescalesetextension_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_virtualmachinescalesetextension_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_virtualmachinescalesetinstance_facts, azure_rm_virtualmachinescalesetinstance_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_virtualmachinescalesetinstance_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_virtualnetwork_facts, azure_rm_virtualnetwork_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_virtualnetwork_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_virtualnetworkpeering_facts, azure_rm_virtualnetworkpeering_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_virtualnetworkpeering_info instead  (https://github.com/ansible-collections/community.azure/pull/31).
- azure_rm_webapp_facts, azure_rm_webapp_info - the deprecated modules have been removed. Use azure.azcollection.azure_rm_webapp_info instead  (https://github.com/ansible-collections/community.azure/pull/31).

v1.1.0
======

Release Summary
---------------

The community.azure Ansible collection is being deprecated in favor of azure.azcollection which provide the same modules in addition to maintenance and updates (https://github.com/ansible-collections/community.azure/pull/24).

Deprecated Features
-------------------

- All community.azure.azure_rm_<resource>_facts modules are deprecated. Use azure.azcollection.azure_rm_<resource>_info modules instead (https://github.com/ansible-collections/community.azure/pull/24).
- All community.azure.azure_rm_<resource>_info modules are deprecated. Use azure.azcollection.azure_rm_<resource>_info modules instead (https://github.com/ansible-collections/community.azure/pull/24).
- community.azure.azure_rm_managed_disk and community.azure.azure_rm_manageddisk are deprecated. Use azure.azcollection.azure_rm_manageddisk instead (https://github.com/ansible-collections/community.azure/pull/24).
- community.azure.azure_rm_virtualmachine_extension and community.azure.azure_rm_virtualmachineextension are deprecated. Use azure.azcollection.azure_rm_virtualmachineextension instead (https://github.com/ansible-collections/community.azure/pull/24).
- community.azure.azure_rm_virtualmachine_scaleset and community.azure.azure_rm_virtualmachinescaleset are deprecated. Use azure.azcollection.azure_rm_virtualmachinescaleset instead (https://github.com/ansible-collections/community.azure/pull/24).

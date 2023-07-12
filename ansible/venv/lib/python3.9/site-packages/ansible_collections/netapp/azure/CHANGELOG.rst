=================================================
Azure NetApp Files (ANF) Collection Release Notes
=================================================

.. contents:: Topics


v21.10.0
========

Minor Changes
-------------

- PR1 - allow usage of Ansible module group defaults - for Ansible 2.12+.

v21.9.0
=======

Minor Changes
-------------

- azure_rm_netapp_volume - new option ``feature_flags`` to selectively enable/disable a feature.

Bugfixes
--------

- azure_rm_netapp_volume - 'Change Ownership' is not permitted when creating NFSv4.1 volume with latest azure-mgmt-netapp package (4.0.0).

v21.8.1
=======

Bugfixes
--------

- Hub Automation cannot generate documentation (cannot use doc fragments from another collection).

v21.8.0
=======

Bugfixes
--------

- fix CI pipeline as azcollection does not support python 2.6.
- fix CI pipeline as ignores are not required with latest azcollection.

v21.7.0
=======

Bugfixes
--------

- fix CI pipeline to work with azcollection, and isolate UTs from azcollection.

v21.6.0
=======

Minor Changes
-------------

- azure_rm_netapp_account - support additional authentication schemes provided by AzureRMModuleBase.
- azure_rm_netapp_capacity_pool - support additional authentication schemes provided by AzureRMModuleBase, and tags.
- azure_rm_netapp_capacity_pool - wait for completion when creating, modifying, or deleting a pool.
- azure_rm_netapp_snapshot - support additional authentication schemes provided by AzureRMModuleBase.
- azure_rm_netapp_snapshot - wait for completion when creating, modifying, or deleting a pool.
- azure_rm_netapp_volume - support additional authentication schemes provided by AzureRMModuleBase, and tags.

v21.5.0
=======

Minor Changes
-------------

- azure_rm_netapp_volume - enable changes in volume size.
- azure_rm_netapp_volume - rename msg to mount_path, as documented in RETURN.

v21.3.0
=======

Minor Changes
-------------

- azure_rm_netapp_account - new option ``active_directories`` to support SMB volumes.
- azure_rm_netapp_account - new suboptions ``ad_name``, ``kdc_ip``, ``service_root_ca_certificate``` for Active Directory.
- azure_rm_netapp_volume - new option ``protocol_types`` to support SMB volumes.

Bugfixes
--------

- azure_rm_netapp_account - wait for job completion for asynchroneous requests, and report belated errors.
- support for azure-mgmt-netapp 1.0.0, while maintaining compatibility with 0.10.0.

v21.2.0
=======

Minor Changes
-------------

- azure_rm_netapp_account - new option ``active_directories`` to support SMB volumes.
- azure_rm_netapp_volume - new option ``protocol_types`` to support SMB volumes.
- azure_rm_netapp_volume - new option ``subnet_name`` as subnet_id is ambiguous.  subnet_id is now aliased to subnet_name.

Bugfixes
--------

- azure_rm_netapp_volume - fix 'Nonetype' object is not subscriptable exception when mount target is not created.

v20.8.0
=======

Minor Changes
-------------

- azure_rm_netapp_capacity_pool - Updated ANF capacity pool modify function for size parameter mandatory issue.
- use a three group format for version_added. So 2.7 becomes 2.7.0. Same thing for 2.8 and 2.9.

v20.7.0
=======

Bugfixes
--------

- azure_rm_netapp_capacity_pool - fixed idempotency for delete operation.

v20.6.0
=======

Minor Changes
-------------

- azure_rm_netapp_capacity_pool - now allows modify for size.
- azure_rm_netapp_volume - now returns complete mount_path of the volume specified.

v20.5.0
=======

Minor Changes
-------------

- azure_rm_netapp_account - new option ``tags``.
- azure_rm_netapp_capacity_pool - new option ``service_level``.
- azure_rm_netapp_volume - new option ``size``.
- azure_rm_netapp_volume - new option ``vnet_resource_group_for_subnet``, resource group for virtual_network and subnet_id to be used.
- azure_rm_netapp_volume - now returns mount_path of the volume specified.

v20.4.0
=======

Bugfixes
--------

- fix changes to azure-mgmt-netapp as per new release.
- removed ONTAP dependency import.

v20.2.0
=======

Bugfixes
--------

- galaxy.yml - fix path to github repository.

v19.10.0
========

New Modules
-----------

- netapp.azure.azure_rm_netapp_account - Manage NetApp Azure Files Account
- netapp.azure.azure_rm_netapp_capacity_pool - Manage NetApp Azure Files capacity pool
- netapp.azure.azure_rm_netapp_snapshot - Manage NetApp Azure Files Snapshot
- netapp.azure.azure_rm_netapp_volume - Manage NetApp Azure Files Volume

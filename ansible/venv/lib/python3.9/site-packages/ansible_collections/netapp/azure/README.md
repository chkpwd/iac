[![Documentation](https://img.shields.io/badge/docs-brightgreen.svg)](https://docs.ansible.com/ansible/devel/collections/netapp/azure/index.html)
![example workflow](https://github.com/ansible-collections/netapp.azure/actions/workflows/main.yml/badge.svg)
[![codecov](https://codecov.io/gh/ansible-collections/netapp.azure/branch/main/graph/badge.svg?token=weBYkksxSi)](https://codecov.io/gh/ansible-collections/netapp.azure)
=============================================================

netapp.azure

Azure NetApp Files (ANF) Collection

Copyright (c) 2019 NetApp, Inc. All rights reserved.
Specifications subject to change without notice.

=============================================================

# Installation
```bash
ansible-galaxy collection install netapp.azure
```
To use Collection add the following to the top of your playbook, with out this you will be using Ansible 2.9 version of the module
```  
collections:
  - netapp.azure
```

# Module documentation
https://docs.ansible.com/ansible/devel/collections/netapp/azure/

# Need help
Join our Slack Channel at [Netapp.io](http://netapp.io/slack)

# Requirements
- python >= 2.7
- azure >= 2.0.0
- Python azure-mgmt. Install using ```pip install azure-mgmt```
- Python azure-mgmt-netapp. Install using ```pip install azure-mgmt-netapp```
- For authentication with Azure NetApp log in before you run your tasks or playbook with 'az login'.

# Code of Conduct
This collection follows the [Ansible project's Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html).

# Release Notes

## 21.10.0

### Minor changes
  - all modules - allow usage of Ansible module group defaults - for Ansible 2.12+.

## 21.9.0

### New Options
  - azure_rm_netapp_volume - `feature_flags` to selectively enable/disable a feature.

### Bug Fixes
  - azure_rm_netapp_volume - 'Change Ownership' is not permitted when creating NFSv4.1 volume with latest azure-mgmt-netapp package (4.0.0).

## 21.8.1

### Bug Fixes
  - Hub Automation cannot generate documentation (cannot use doc fragments from another collection).

## 21.8.0

### Bug Fixes

- fix CI pipeline as azcollection does not support python 2.6.
- fix CI pipeline as ignores are not required with latest azcollection.

## 21.7.0

### Bug Fixes

- fix CI pipeline to work with azcollection, and isolate UTs from azcollection.

## 21.6.0

### Minor changes

  - azure_rm_netapp_account - support additional authentication schemes provided by AzureRMModuleBase.
  - azure_rm_netapp_capacity_pool - support additional authentication schemes provided by AzureRMModuleBase, and tags.
  - azure_rm_netapp_capacity_pool - wait for completion when creating, modifying, or deleting a pool.
  - azure_rm_netapp_snapshot - support additional authentication schemes provided by AzureRMModuleBase.
  - azure_rm_netapp_snapshot - wait for completion when creating or deleting a snapshot.
  - azure_rm_netapp_volume - support additional authentication schemes provided by AzureRMModuleBase, and tags.

## 21.5.0

### Minor changes
  - azure_rm_netapp_volume - enable changes in volume size.
  - azure_rm_netapp_volume - rename msg to mount_path, as documented in RETURN.

## 21.3.0

### New Options
  - azure_rm_netapp_account - new suboptions `ad_name`, `kdc_ip`, `service_root_ca_certificate` for Active Directory.

### Bug Fixes
  - support for azure-mgmt-netapp 1.0.0, while maintaining compatibility with 0.10.0.
  - azure_rm_netapp_account - wait for job completion for asynchroneous requests, and report belated errors.

## 21.2.0

### New Options
  - azure_rm_netapp_account: new option `active_directories` to support SMB volumes.
  - azure_rm_netapp_volume: new option `protocol_types` to support SMB volumes.

## 21.1.0

### New Options
  - azure_rm_netapp_volume - new option `subnet_name` as subnet_id is ambiguous.  subnet_id is now aliased to subnet_name.

### Bug Fixes
  - azure_rm_netapp_volume - fix 'Nonetype' object is not subscriptable exception when mount target is not created.

## 20.8.0

### Module documentation changes
- azure_rm_netapp_capacity_pool: Updated ANF capacity pool modify function for `size` parameter mandatory issue.
- use a three group format for `version_added`.  So 2.7 becomes 2.7.0.  Same thing for 2.8 and 2.9.

## 20.7.0

### Bug Fixes
- azure_rm_netapp_capacity_pool: fixed idempotency for delete operation.

## 20.6.0

### New Options
- azure_rm_netapp_capacity_pool: now allows modify for size.
- azure_rm_netapp_volume: now returns complete mount_path of the volume specified.

## 20.5.0

### New Options
- azure_rm_netapp_account: new option `tags`.
- azure_rm_netapp_capacity_pool: new option `service_level`.
- azure_rm_netapp_volume: new option `size`.
- azure_rm_netapp_volume: now returns mount_path of the volume specified.
- azure_rm_netapp_volume: new option `vnet_resource_group_for_subnet`, resource group for virtual_network and subnet_id to be used.

## 20.4.0

### Bug Fixes
- fix changes to azure-mgmt-netapp as per new release.
- removed ONTAP dependency import.

## 20.2.0

### Bug Fixes
- galaxy.yml: fix path to github repository.

## 19.11.0
- Initial release.
### New Modules
- azure_rm_netapp_account: create/delete NetApp Azure Files Account.
- azure_rm_netapp_capacity_pool: create/delete NetApp Azure Files capacity pool.
- azure_rm_netapp_snapshot: create/delete NetApp Azure Files Snapshot.
- azure_rm_netapp_volume: create/delete NetApp Azure Files volume.

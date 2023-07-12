<a href="https://github.com/Pure-Storage-Ansible/FlashBlade-Collection/releases/latest"><img src="https://img.shields.io/github/v/tag/Pure-Storage-Ansible/FlashBlade-Collection?label=release">
<a href="COPYING.GPLv3"><img src="https://img.shields.io/badge/license-GPL%20v3.0-brightgreen.svg"></a>
<img src="https://cla-assistant.io/readme/badge/Pure-Storage-Ansible/FlashBlade-Collection">
<img src="https://github.com/Pure-Storage-Ansible/FLashBlade-Collection/workflows/Pure%20Storage%20Ansible%20CI/badge.svg">
<a href="https://github.com/psf/black"><img src="https://img.shields.io/badge/code%20style-black-000000.svg"></a>
    
# Pure Storage FlashBlade Collection

The Pure Storage FlashBlade collection consists of the latest versions of the FlashBlade modules.

## Supported Platforms

- Pure Storage FlashBlade with Purity 2.1.2 or later
- Certain modules and functionality require higher versions of Purity. Modules will inform you if your Purity version is not high enough to use a module.

## Prerequisites

- Ansible 2.9 or later
- Pure Storage FlashBlade system running Purity//FB 2.1.2 or later
    - some modules require higher versions of Purity//FB
- purity_fb >=v1.12.2
- py-pure-client >=v1.27.0
- python >=3.6
- netaddr
- datetime
- pytz

## Idempotency

All modules are idempotent with the exception of modules that change or set passwords. Due to security requirements exisitng passwords can be validated against and therefore will always be modified, even if there is no change.

## Available Modules

- purefb_ad - manage Active Directory account on FlashBlade
- purefb_alert - manage alert email settings on a FlashBlade
- purefb_apiclient - manage API clients for FlashBlade
- purefb_banner - manage FlashBlade login banner
- purefb_bladename - manage FlashBlade name
- purefb_bucket - manage S3 buckets on a FlashBlade
- purefb_bucket_replica - manage bucket replica links on a FlashBlade
- purefb_certgrp - manage FlashBlade certificate groups
- purefb_certs - manage FlashBlade SSL certificates
- purefb_connect - manage connections between FlashBlades
- purefb_dns - manage DNS settings on a FlashBlade
- purefb_ds - manage Directory Services settings on a FlashBlade
- purefb_dsrole - manage Directory Service Roles on a FlashBlade
- purefb_eula - manage EULA on FlashBlade
- purefb_fs - manage filesystems on a FlashBlade
- purefb_fs_replica - manage filesystem replica links on a FlashBlade
- purefb_groupquota - manage individual group quotas on FlashBlade filesystems
- purefb_info - get information about the configuration of a FlashBlade
- purefb_inventory - get information about the hardware inventory of a FlashBlade
- purefb_keytabs - manage FlashBlade Kerberos keytabs
- purefb_lag - manage FlashBlade Link Aggregation Groups
- purefb_lifecycle - manage FlashBlade Bucket Lifecycle Rules
- purefb_messages - list FlashBlade alert messages
- purefb_network - manage the network settings for a FlashBlade
- purefb_ntp - manage the NTP settings for a FlashBlade
- purefb_phonehome - manage the phone home settings for a FlashBlade
- purefb_pingtrace - perform FlashBlade network diagnostics
- purefb_policy - manage the filesystem snapshot policies for a FlashBlade
- purefb_proxy - manage the phone home HTTP proxy settings for a FlashBlade
- purefb_ra - manage the Remote Assist connections on a FlashBlade
- purefb_remote_cred - manage the Object Store Remote Credentials on a FlashBlade
- purefb_s3acc - manage the object store accounts on a FlashBlade
- purefb_s3user - manage the object atore users on a FlashBlade
- purefb_smtp - manage SMTP settings on a FlashBlade
- purefb_snap - manage filesystem snapshots on a FlashBlade
- purefb_snmp_agent - modify the FlashBlade SNMP Agent
- purefb_snmp_mgr - manage SNMP Managers on a FlashBlade
- purefb_subnet - manage network subnets on a FlashBlade
- purefb_syslog - manage FlashBlade syslog server configuration
- purefb_target - manage remote S3-capable targets for a FlashBlade
- purefb_timeout - manage FlashBlade GUI timeout
- purefb_user - manage local *pureuser* account password on a FlashBlade
- purefb_userpolicy - manage FlashBlade Object Store User Access Policies
- purefb_userquota - manage individual user quotas on FlashBlade filesystems
- purefb_virtualhost - manage FlashBlade Object Store Virtual Hosts

## Instructions

Install the Pure Storage FlashBlade collection on your Ansible management host.

- Using ansible-galaxy (Ansible 2.9 or later):
```
ansible-galaxy collection install purestorage.flashblade -p ~/.ansible/collections
```

All servers that execute the modules must have the appropriate Pure Storage Python SDK installed on the host.

## License

[BSD-2-Clause](https://directory.fsf.org/wiki?title=License:FreeBSD)
[GPL-3.0-or-later](https://www.gnu.org/licenses/gpl-3.0.en.html)

## Author

This collection was created in 2019 by [Simon Dodsley](@sdodsley) for, and on behalf of, the [Pure Storage Ansible Team](pure-ansible-team@purestorage.com)

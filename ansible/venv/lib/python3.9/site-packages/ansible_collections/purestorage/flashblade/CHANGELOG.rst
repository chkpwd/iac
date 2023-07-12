====================================
Purestorage.Flashblade Release Notes
====================================

.. contents:: Topics


v1.11.0
=======

Minor Changes
-------------

- purefb_info - Added `encryption` and `support_keys` information.
- purefb_info - Added bucket quota and safemode information per bucket
- purefb_info - Added security update version for Purity//FB 4.0.2, or higher
- purefb_info - Updated object store account information
- purefb_inventory - Added `part_number` to hardware item information.
- purefb_policy - Added support for multiple rules in snapshot policies
- purefb_proxy - Added new boolean parameter `secure`. Default of true (for backwards compatability) sets the protocol to be `https://`. False sets `http://`
- purefb_s3acc - Added support for default bucket quotas and hard limits
- purefb_s3acc - Added support for object account quota and hard limit

Bugfixes
--------

- purefa_info - Fixed issue when more than 10 buckets have lifecycle rules.
- purefb_s3user - Fix incorrect response when bad key/secret pair provided for new user

New Modules
-----------

- purestorage.flashblade.purefb_pingtrace - Employ the internal FlashBlade ping and trace mechanisms

v1.10.0
=======

Minor Changes
-------------

- All - Update documentation examples with FQCNs
- purefb_ad - Allow service to be a list
- purefb_bucket - Allow setting of bucket type to support VSO - requires Purity//FB 3.3.3 or higher
- purefb_certs - Fix several misspellings of certificate
- purefb_info - Added filesystem default, user and group quotas where available
- purefb_info - Expose object store bucket type from Purity//FB 3.3.3
- purefb_info - Show information for current timezone
- purefb_policy - Allow rename of NFS Export Policies from Purity//FB 3.3.3
- purefb_tz - Add support for FlashBlade timezone management

Bugfixes
--------

- purefb_connect - Resolve connection issues between two FBs that are throttling capable
- purefb_policy - Fix incorrect API call for NFS export policy rule creation

New Modules
-----------

- purestorage.flashblade.purefb_messages - List FlashBlade Alert Messages
- purestorage.flashblade.purefb_tz - Configure Pure Storage FlashBlade timezone

v1.9.0
======

Minor Changes
-------------

- purefb_admin - New module to manage global admin settings
- purefb_connect - Add support for array connections to have bandwidth throttling defined
- purefb_fs - Add support for NFS export policies
- purefb_info - Add NFS export policies and rules
- purefb_info - Show array connections bandwidth throttle information
- purefb_policy - Add NFS export policies, with rules, as a new policy type
- purefb_policy - Add support for Object Store Access Policies, associated rules and user grants
- purefb_policy - New parameter `policy_type` added. For backwards compatability, default to `snapshot` if not provided.

v1.8.1
======

Minor Changes
-------------

- purefb.py - Use latest `pypureclient` SDK with fix for "best fit". No longer requires double login to negotiate best API version.

v1.8.0
======

Minor Changes
-------------

- purefb.py - Add check to ensure FlashBlade uses the latest REST version possible for Purity version installed
- purefb_info - Add object lifecycles rules to bucket subset
- purefb_lifecycle - Add support for updated object lifecycle rules. See documentation for details of new parameters.
- purefb_lifecycle - Change `keep_for` parameter to be `keep_previous_for`. `keep_for` is deprecated and will be removed in a later version.
- purefb_user - Add support for managing user public key and user unlock

Known Issues
------------

- purefb_lag - The mac_address field in the response is not populated. This will be fixed in a future FlashBlade update.

v1.7.0
======

Minor Changes
-------------

- purefb_groupquota - New module for manage individual filesystem group quotas
- purefb_lag - Add support for LAG management
- purefb_snap - Add support for immeadiate snapshot to remote connected FlashBlade
- purefb_subnet - Add support for multiple LAGs.
- purefb_userquota - New module for manage individual filesystem user quotas

Bugfixes
--------

- purefb_fs - Fix bug where changing the state of both NFS v3 and v4.1 at the same time ignored one of these.
- purefb_s3acc - Ensure S3 Account Name is always lowercase
- purefb_s3user - Ensure S3 Account Name is always lowercase
- purefb_subnet - Allow subnet creation with no gateway

New Modules
-----------

- purestorage.flashblade.purefb_groupquota - Manage filesystem group quotas
- purestorage.flashblade.purefb_lag - Manage FlashBlade Link Aggregation Groups
- purestorage.flashblade.purefb_userquota - Manage filesystem user quotas

v1.6.0
======

Minor Changes
-------------

- purefa_virtualhost - New module to manage API Clients
- purefb_ad - New module to manage Active Directory Account
- purefb_eula - New module to sign EULA
- purefb_info - Add Active Directory, Kerberos and Object Store Account information
- purefb_info - Add extra info for Purity//FB 3.2+ systems
- purefb_keytabs - New module to manage Kerberos Keytabs
- purefb_s3user - Add access policy option to user creation
- purefb_timeout - Add module to set GUI idle timeout
- purefb_userpolicy - New module to manage object store user access policies
- purefb_virtualhost - New module to manage Object Store Virtual Hosts

New Modules
-----------

- purestorage.flashblade.purefb_ad - Manage FlashBlade Active Directory Account
- purestorage.flashblade.purefb_apiclient - Manage FlashBlade API Clients
- purestorage.flashblade.purefb_eula - Sign Pure Storage FlashBlade EULA
- purestorage.flashblade.purefb_keytabs - Manage FlashBlade Kerberos Keytabs
- purestorage.flashblade.purefb_timeout - Configure Pure Storage FlashBlade GUI idle timeout
- purestorage.flashblade.purefb_userpolicy - Manage FlashBlade Object Store User Access Policies
- purestorage.flashblade.purefb_virtualhost - Manage FlashBlade Object Store Virtual Hosts

v1.5.0
======

Minor Changes
-------------

- purefb_certs - Add update functionality for array cert
- purefb_fs - Add multiprotocol ACL support
- purefb_info - Add information regarding filesystem multiprotocol (where available)
- purefb_info - Add new parameter to provide details on admin users
- purefb_info - Add replication performace statistics
- purefb_s3user - Add ability to remove an S3 users existing access key

Bugfixes
--------

- purefb_* - Return a correct value for `changed` in all modules when in check mode
- purefb_dns - Deprecate search paramerter
- purefb_dsrole - Resolve idempotency issue
- purefb_lifecycle - Fix error when creating new bucket lifecycle rule.
- purefb_policy - Ensure undeclared variables are set correctly
- purefb_s3user - Fix maximum access_key count logic

v1.4.0
======

Minor Changes
-------------

- purefb_banner - Module to manage the GUI and SSH login message
- purefb_certgrp - Module to manage FlashBlade Certificate Groups
- purefb_certs - Module to create and delete SSL certificates
- purefb_connect - Support idempotency when exisitng connection is incoming
- purefb_fs - Add new options for filesystem control (https://github.com/Pure-Storage-Ansible/FlashBlade-Collection/pull/81)
- purefb_fs - Default filesystem size on creation changes from 32G to ``unlimited``
- purefb_fs - Fix error in deletion and eradication of filesystem
- purefb_fs_replica - Remove condition to attach/detach policies on unhealthy replica-link
- purefb_info - Add support to list filesystem policies
- purefb_lifecycle - Module to manage FlashBlade Bucket Lifecycle Rules
- purefb_s3user - Add support for imported user access keys
- purefb_syslog - Module to manage syslog server configuration

Bugfixes
--------

- purefa_policy - Resolve multiple issues related to incorrect use of timezones
- purefb_connect - Ensure changing encryption status on array connection is performed correctly
- purefb_connect - Fix breaking change created in purity_fb SDK 1.9.2 for deletion of array connections
- purefb_connect - Hide target array API token
- purefb_ds - Ensure updating directory service configurations completes correctly
- purefb_info - Fix issue getting array info when encrypted connection exists

New Modules
-----------

- purestorage.flashblade.purefb_banner - Configure Pure Storage FlashBlade GUI and SSH MOTD message
- purestorage.flashblade.purefb_certgrp - Manage FlashBlade Certifcate Groups
- purestorage.flashblade.purefb_certs - Manage FlashBlade SSL Certifcates
- purestorage.flashblade.purefb_lifecycle - Manage FlashBlade object lifecycles
- purestorage.flashblade.purefb_syslog - Configure Pure Storage FlashBlade syslog settings

v1.3.0
======

Release Summary
---------------

| Release Date: 2020-08-08
| This changlelog describes all changes made to the modules and plugins included in this collection since Ansible 2.9.0


Major Changes
-------------

- purefb_alert - manage alert email settings on a FlashBlade
- purefb_bladename - manage FlashBlade name
- purefb_bucket_replica - manage bucket replica links on a FlashBlade
- purefb_connect - manage connections between FlashBlades
- purefb_dns - manage DNS settings on a FlashBlade
- purefb_fs_replica - manage filesystem replica links on a FlashBlade
- purefb_inventory - get information about the hardware inventory of a FlashBlade
- purefb_ntp - manage the NTP settings for a FlashBlade
- purefb_phonehome - manage the phone home settings for a FlashBlade
- purefb_policy - manage the filesystem snapshot policies for a FlashBlade
- purefb_proxy - manage the phone home HTTP proxy settings for a FlashBlade
- purefb_remote_cred - manage the Object Store Remote Credentials on a FlashBlade
- purefb_snmp_agent - modify the FlashBlade SNMP Agent
- purefb_snmp_mgr - manage SNMP Managers on a FlashBlade
- purefb_target - manage remote S3-capable targets for a FlashBlade
- purefb_user - manage local ``pureuser`` account password on a FlashBlade

Minor Changes
-------------

- purefb_bucket - Versioning support added
- purefb_info - new options added for information collection
- purefb_network - Add replication service type
- purefb_s3user - Limit ``access_key`` recreation to 3 times
- purefb_s3user - return dict changed from ``ansible_facts`` to ``s3user_info``

Bugfixes
--------

- purefb_bucket - Add warning message if ``state`` is ``absent`` without ``eradicate:``
- purefb_fs - Add graceful exist when ``state`` is ``absent`` and filesystem not eradicated
- purefb_fs - Add warning message if ``state`` is ``absent`` without ``eradicate``

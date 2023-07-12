====================================
Purestorage.Flasharray Release Notes
====================================

.. contents:: Topics


v1.19.1
=======

Bugfixes
--------

- purefa_info - Fixed missing arguments for google_offload and pods

v1.19.0
=======

New Modules
-----------

- purestorage.flasharray.purefa_logging - Manage Pure Storage FlashArray Audit and Session logs

v1.18.0
=======

Release Summary
---------------

| FlashArray Collection v1.18 removes module-side support for Python 2.7.
| The minimum required Python version for the FlashArray Collection is Python 3.6.


Minor Changes
-------------

- purefa_hg - Changed parameter hostgroup to name for consistency. Added hostgroup as an alias for backwards compatability.
- purefa_hg - Exit gracefully, rather than failing when a specified volume does not exist
- purefa_host - Exit gracefully, rather than failing when a specified volume does not exist
- purefa_info - Added network neighbors info to `network` subset
- purefa_pod - Added support for pod quotas (from REST 2.23)
- purefa_snap - New response of 'suffix' when snapshot has been created.
- purefa_volume - Added additional volume facts for volume update, or for no change

Bugfixes
--------

- purefa_network - Resolves network port setting idempotency issue
- purefa_pg - Fixed issue where volumes could not be added to a PG when one of the arrays was undergoing a failover.
- purefa_snap - Fixed issue system generated suffixes not being allowed and removed unnecessary warning message.

v1.17.2
=======

v1.17.1
=======

Bugfixes
--------

- purefa_info - Fix REST response backwards compatibility issue for array capacity REST response
- purefa_info - Resolves issue in AC environment where REST v2 host list mismatches REST v1 due to remote hosts.
- purefa_info - Resolves issue with destroyed pgroup snapshot on an offload target not have a time remaining value
- purefa_pg - Resolves issue with destroyed pgroup snapshot on an offload target not have a time remaining value

v1.17.0
=======

Minor Changes
-------------

- purefa_network - Added support for NVMe-RoCE and NVMe-TCP service types
- purefa_user - Added Ops Admin role to choices
- purefa_vlan - Added support for NVMe-TCP service type

Bugfixes
--------

- purefa_host - Fixed parameter name
- purefa_info - Fix missing FC target ports for host
- purefa_pgsched - Fix error when setting schedule for pod based protection group
- purefa_vg - Fix issue with VG creation on newer Purity versions
- purefa_volume - Ensure promotion_stateus is returned correctly on creation
- purefa_volume - Fix bug when overwriting volume using invalid parmaeters
- purefa_volume - Fixed idempotency bug when creating volumes with QoS

v1.16.2
=======

v1.16.1
=======

Bugfixes
--------

- purefa_volume - Fixed issue with promotion status not being called correctly

v1.16.0
=======

Minor Changes
-------------

- purefa_host - Add support for VLAN ID tagging for a host (Requires Purity//FA 6.3.5)
- purefa_info - Add new subset alerts
- purefa_info - Added default protection information to `config` section
- purefa_volume - Added support for volume promotion/demotion

Bugfixes
--------

- purefa - Remove unneeded REST version check as causes issues with REST mismatches
- purefa_ds - Fixed dict syntax error
- purefa_info - Fiexed issue with DNS reporting in Purity//FA 6.4.0 with non-FA-File system
- purefa_info - Fixed error in policies subsection due to API issue
- purefa_info - Fixed race condition with protection groups
- purefa_smtp - Fix parameter name

New Modules
-----------

- purestorage.flasharray.purefa_snmp_agent - Configure the FlashArray SNMP Agent

v1.15.0
=======

Minor Changes
-------------

- purefa_network - Added support for servicelist updates
- purefa_vlan - Extend VLAN support to cover NVMe-RoCE and file interfaces

Bugfixes
--------

- purefa.py - Fix issue in Purity versions numbers that are for development versions
- purefa_policy - Fixed missing parameters in function calls
- purefa_vg - Fix typeerror when using newer Purity versions and setting VG QoS

v1.14.0
=======

Minor Changes
-------------

- purefa_ad - Add support for TLS and joining existing AD account
- purefa_dns - Support multiple DNS configurations from Puritry//FA 6.3.3
- purefa_info - Add NFS policy user mapping status
- purefa_info - Add support for Virtual Machines and Snapshots
- purefa_info - Ensure global admin lockout duration is measured in seconds
- purefa_info - Support multiple DNS configurations
- purefa_inventory - Add REST 2.x support and SFP details for Purity//FA 6.3.4 and higher
- purefa_inventory - Change response dict name to `purefa_inv` so doesn't clash with info module response dict
- purefa_inventory - add chassis information to inventory
- purefa_pg - Changed parameter `pgroup` to `name`. Allow `pgroup` as alias for backwards compatability.
- purefa_policy - Add ``all_squash``, ``anonuid`` and ``anongid`` to NFS client rules options
- purefa_policy - Add support for NFS policy user mapping
- purefa_volume - Default Protection Group support added for volume creation and copying from Purity//FA 6.3.4

Bugfixes
--------

- purefa_dns - Corrects logic where API responds with an empty list rather than a list with a single empty string in it.
- purefa_ds - Add new parameter `force_bind_password` (default = True) to allow idempotency for module
- purefa_hg - Ensure volume disconnection from a hostgroup is idempotent
- purefa_ntp - Corrects workflow so that the state between desired and current are checked before marking the changed flag to true during an absent run
- purefa_pg - Corredt issue when target for protection group is not correctly amended
- purefa_pg - Ensure deleted protection group can be correctly recovered
- purefa_pg - Fix idempotency issue for protection group targets
- purefa_pgsched - Allow zero as a valid value for appropriate schedule parameters
- purefa_pgsched - Fix issue where 0 was not correctly handled for replication schedule
- purefa_pgsnap - Resolved intermittent error where `latest` snapshot is not complete and can fail. Only select latest completed snapshot to restore from.

New Modules
-----------

- purestorage.flasharray.purefa_default_protection - Manage SafeMode default protection for a Pure Storage FlashArray
- purestorage.flasharray.purefa_messages - List FlashArray Alert Messages

v1.13.0
=======

Minor Changes
-------------

- purefa_fs - Add support for replicated file systems
- purefa_info - Add QoS information for volume groups
- purefa_info - Add info for protection group safe mode setting (Requires Purity//FA 6.3.0 or higher)
- purefa_info - Add info for protection group snapshots
- purefa_info - Add priority adjustment information for volumes and volume groups
- purefa_info - Split volume groups into live and deleted dicts
- purefa_pg - Add support for protection group SafeMode. Requires Purity//FA 6.3.0 or higher
- purefa_policy - Allow directories in snapshot policies to be managed
- purefa_vg - Add DMM Priority Adjustment support
- purefa_volume - Add support for DMM Priority Adjustment
- purefa_volume - Provide volume facts for volume after recovery

Bugfixes
--------

- purefa_host - Allow multi-host creation without requiring a suffix string
- purefa_info - Fix issue where remote arrays are not in a valid connected state
- purefa_policy - Fix idempotency issue with quota policy rules
- purefa_policy - Fix issue when creating multiple rules in an NFS policy

v1.12.1
=======

Minor Changes
-------------

- All modules - Change examples to use FQCN for module

Bugfixes
--------

- purefa_info - Fix space reporting issue
- purefa_subnet - Fix subnet update checks when no gateway in existing subnet configuration

v1.12.0
=======

Minor Changes
-------------

- purefa_admin - New module to set global admin settings, inclusing SSO
- purefa_dirsnap - Add support to rename directory snapshots not managed by a snapshot policy
- purefa_info - Add SAML2SSO configutration information
- purefa_info - Add Safe Mode status
- purefa_info - Fix Active Directory configuration details
- purefa_network - Resolve bug stopping management IP address being changed correctly
- purefa_offload - Add support for multiple, homogeneous, offload targets
- purefa_saml - Add support for SAML2 SSO IdPs
- purefa_volume - Provide volume facts in all cases, including when no change has occured.

Deprecated Features
-------------------

- purefa_sso - Deprecated in favor of M(purefa_admin). Will be removed in Collection 2.0

Bugfixes
--------

- purefa_certs - Allow a certificate to be imported over an existing SSL certificate
- purefa_eula - Reolve EULA signing issue
- purefa_network - Fix bug introduced with management of FC ports
- purefa_policy - Fix issue with SMB Policy creation

Known Issues
------------

- purefa_admin - Once `max_login` and `lockout` have been set there is currently no way to rest these to zero except through the FlashArray GUI

New Modules
-----------

- purestorage.flasharray.purefa_admin - Configure Pure Storage FlashArray Global Admin settings
- purestorage.flasharray.purefa_saml - Manage FlashArray SAML2 service and identity providers

v1.11.0
=======

Minor Changes
-------------

- purefa_host - Deprecate ``protocol`` parameter. No longer required.
- purefa_info - Add NVMe NGUID value for volumes
- purefa_info - Add array, volume and snapshot detailed capacity information
- purefa_info - Add deleted members to volume protection group info
- purefa_info - Add snapshot policy rules suffix support
- purefa_info - Remove directory_services field. Deprecated in Collections 1.6
- purefa_policy - Add snapshot policy rules suffix support
- purefa_syslog_settings - Add support to manage global syslog server settings
- purefa_volume - Add NVMe NGUID to response dict

Bugfixes
--------

- purefa_subnet - Add regex to check for correct dsubnet name
- purefa_user - Add regex to check for correct username

v1.10.0
=======

Minor Changes
-------------

- purefa_ds - Add ``join_ou`` parameter for AD account creation
- purefa_kmip - Add support for KMIP server management

New Modules
-----------

- purestorage.flasharray.purefa_kmip - Manage FlashArray KMIP server objects

v1.9.0
======

Minor Changes
-------------

- purefa_ad - Increase number of kerberos and directory servers to be 3 for each.
- purefa_ad - New module to manage Active Directory accounts
- purefa_dirsnap - New modules to manage FA-Files directory snapshots
- purefa_eradication - New module to set deleted items eradication timer
- purefa_info - Add data-at-rest and eradication timer information to default dict
- purefa_info - Add high-level count for directory quotas and details for all FA-Files policies
- purefa_info - Add volume Page 83 NAA information for volume details
- purefa_network - Add support for enable/diable FC ports
- purefa_policy - Add support for FA-files Directory Quotas and associated rules and members
- purefa_sso - Add support for setting FlashArray Single Sign-On from Pure1 Manage
- purefa_volume - Add volume Page 83 NAA information to response dict

Bugfixes
--------

- purefa_host - Rollback host creation if initiators already used by another host
- purefa_policy - Fix incorrect protocol endpoint invocation
- purefa_ra - fix disable feature for remote assist, this didn't work due to error in check logic
- purefa_vg - Correct issue when setting or changing Volume Group QoS
- purefa_volume - Fix incorrect API version check for ActiveDR support

New Modules
-----------

- purestorage.flasharray.purefa_ad - Manage FlashArray Active Directory Account
- purestorage.flasharray.purefa_dirsnap - Manage FlashArray File System Directory Snapshots
- purestorage.flasharray.purefa_eradication - Configure Pure Storage FlashArray Eradication Timer
- purestorage.flasharray.purefa_sso - Configure Pure Storage FlashArray Single Sign-On

v1.8.0
======

Minor Changes
-------------

- purefa_certs - New module for managing SSL certificates
- purefa_volume - New parameter pgroup to specify an existing protection group to put crwated volume(s) in.

Bugfixes
--------

- purefa_dsrole - If using None for group or group_base incorrect change state applied
- purefa_network - Allow gateway paremeter to be set as None - needed for non-routing iSCSI ports
- purefa_pg - Check to ensure protection group name meets naming convention
- purefa_pgsnap - Fail with warning if trying to restore to a stretched ActiveCluster pod
- purefa_volume - Ensure REST version is high enough to support promotion_status

New Modules
-----------

- purestorage.flasharray.purefa_certs - Manage FlashArray SSL Certificates

v1.7.0
======

Minor Changes
-------------

- purefa_maintenance - New module to set maintenance windows
- purefa_pg - Add support to rename protection groups
- purefa_syslog - Add support for naming SYSLOG servers for Purity//FA 6.1 or higher

Bugfixes
--------

- purefa_info - Fix missing protection group snapshot info for local snapshots
- purefa_info - Resolve crash when an offload target is offline
- purefa_pgsnap - Ensure suffix rules only implemented for state=present
- purefa_user - Do not allow role changed for breakglass user (pureuser)
- purefa_user - Do not change role for existing user unless requested

New Modules
-----------

- purestorage.flasharray.purefa_maintenance - Configure Pure Storage FlashArray Maintence Windows

v1.6.2
======

Bugfixes
--------

- purefa_volume - Fix issues with moving volumes into demoted or linked pods

v1.6.0
======

Minor Changes
-------------

- purefa_connect - Add support for FC-based array replication
- purefa_ds - Add Purity v6 support for Directory Services, including Data DS and updating services
- purefa_info - Add support for FC Replication
- purefa_info - Add support for Remote Volume Snapshots
- purefa_info - Update directory_services dictionary to cater for FA-Files data DS. Change DS dict forward. Add deprecation warning.
- purefa_ntp - Ignore NTP configuration for CBS-based arrays
- purefa_pg - Add support for Protection Groups in AC pods
- purefa_snap - Add support for remote snapshot of individual volumes to offload targets

Bugfixes
--------

- purefa_hg - Ensure all hostname chacks are lowercase for consistency
- purefa_pgsnap - Add check to ensure suffix name meets naming conventions
- purefa_pgsnap - Ensure pgsnap restores work for AC PGs
- purefa_pod - Ensure all pod names are lowercase for consistency
- purefa_snap - Update suffix regex pattern
- purefa_volume - Add missing variable initialization

v1.5.1
======

Minor Changes
-------------

- purefa_host - Add host rename function
- purefa_host - Add support for multi-host creation
- purefa_vg - Add support for multiple vgroup creation
- purefa_volume - Add support for multi-volume creation

Bugfixes
--------

- purefa.py - Resolve issue when pypureclient doesn't handshake array correctly
- purefa_dns - Fix idempotency
- purefa_volume - Alert when volume selected for move does not exist

v1.5.0
======

Minor Changes
-------------

- purefa_apiclient - New module to support API Client management
- purefa_directory - Add support for managed directories
- purefa_export - Add support for filesystem exports
- purefa_fs - Add filesystem management support
- purefa_hg - Enforce case-sensitivity rules for hostgroup objects
- purefa_host - Enforce hostname case-sensitivity rules
- purefa_info - Add support for FA Files features
- purefa_offload - Add support for Google Cloud offload target
- purefa_pg - Enforce case-sensitivity rules for protection group objects
- purefa_policy - Add support for NFS, SMB and Snapshot policy management

Bugfixes
--------

- purefa_host - Correctly remove host that is in a hostgroup
- purefa_volume - Fix failing idempotency on eradicate volume

New Modules
-----------

- purestorage.flasharray.purefa_apiclient - Manage FlashArray API Clients
- purestorage.flasharray.purefa_directory - Manage FlashArray File System Directories
- purestorage.flasharray.purefa_export - Manage FlashArray File System Exports
- purestorage.flasharray.purefa_fs - Manage FlashArray File Systems
- purestorage.flasharray.purefa_policy - Manage FlashArray File System Policies

v1.4.0
======

Release Summary
---------------

| Release Date: 2020-08-08
| This changlelog describes all changes made to the modules and plugins included in this collection since Ansible 2.9.0


Major Changes
-------------

- purefa_console - manage Console Lock setting for the FlashArray
- purefa_endpoint - manage VMware protocol-endpoints on the FlashArray
- purefa_eula - sign, or resign, FlashArray EULA
- purefa_inventory - get hardware inventory information from a FlashArray
- purefa_network - manage the physical and virtual network settings on the FlashArray
- purefa_pgsched - manage protection group snapshot and replication schedules on the FlashArray
- purefa_pod - manage ActiveCluster pods in FlashArrays
- purefa_pod_replica - manage ActiveDR pod replica links in FlashArrays
- purefa_proxy - manage the phonehome HTTPS proxy setting for the FlashArray
- purefa_smis - manage SMI-S settings on the FlashArray
- purefa_subnet - manage network subnets on the FlashArray
- purefa_timeout - manage the GUI idle timeout on the FlashArray
- purefa_vlan - manage VLAN interfaces on the FlashArray
- purefa_vnc - manage VNC for installed applications on the FlashArray
- purefa_volume_tags - manage volume tags on the FlashArray

Minor Changes
-------------

- purefa_hg - All LUN ID to be set for single volume
- purefa_host - Add CHAP support
- purefa_host - Add support for Cloud Block Store
- purefa_host - Add volume disconnection support
- purefa_info - Certificate times changed to human readable rather than time since epoch
- purefa_info - new options added for information collection
- purefa_info - return dict names changed from ``ansible_facts`` to ``ra_info`` and ``user_info`` in approproate sections
- purefa_offload - Add support for Azure
- purefa_pgsnap - Add offload support
- purefa_snap - Allow recovery of deleted snapshot
- purefa_vg - Add QoS support

Bugfixes
--------

- purefa_host - resolve hostname case inconsistencies
- purefa_host - resolve issue found when using in Pure Storage Test Drive

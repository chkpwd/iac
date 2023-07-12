==============================
Vultr Collection Release Notes
==============================

.. contents:: Topics


v1.8.0
======

Minor Changes
-------------

- instance - Implemented a new ``state`` equal ``reinstalled`` to reinstall an existing instance (https://github.com/vultr/ansible-collection-vultr/pull/66).
- inventory - Bare metal support has been implemented (https://github.com/vultr/ansible-collection-vultr/pull/63).

v1.7.1
======

Bugfixes
--------

- instance - Fixed an issue when deleting an instance in locked state. (https://github.com/vultr/ansible-collection-vultr/pull/68)
- inventory - Fixed the issue instance tags were not returned (https://github.com/vultr/ansible-collection-vultr/issues/69)

v1.7.0
======

Minor Changes
-------------

- instance - Added argument ``snapshot`` to support creation of instances via snapshot (https://github.com/vultr/ansible-collection-vultr/pull/56).

New Modules
-----------

- snapshot - Manages snapshots on Vultr
- snapshot_info - Gather information about the Vultr snapshots

v1.6.0
======

Minor Changes
-------------

- inventory - Added IPv6 support by adding ``v6_main_ip`` to the attributes and improved docs (https://github.com/vultr/ansible-collection-vultr/pull/54).

v1.5.1
======

Bugfixes
--------

- instance - An error that caused the start script not to be processed has been fixed. (https://github.com/vultr/ansible-collection-vultr/issues/49)
- instance_info - The problem that the module was missing in the runtime action group has been fixed.

v1.5.0
======

Minor Changes
-------------

- instance - Implemented VPC support to attach/detach VPCs (https://github.com/vultr/ansible-collection-vultr/pull/46).

New Modules
-----------

- instance_info - Get information about the Vultr instances

v1.4.0
======

New Plugins
-----------

Inventory
~~~~~~~~~

- vultr - Retrieves list of instances via Vultr v2 API

v1.3.1
======

Bugfixes
--------

- instance - Fixed an issue with ssh keys being ignored when deploying an new instance.

v1.3.0
======

Bugfixes
--------

- instance - Fixed the handling for activating/deactivating backups.

v1.2.0
======

Minor Changes
-------------

- block_storage - Added the parameter ``block_type`` to configure block types, default value is ``high_perf``.
- dns_record - Removed the default value ``0`` for the optional parameter ``priority``.

v1.1.0
======

Minor Changes
-------------

- block_storage - the default value for parameter ``live`` while attaching a volume changed to a more sensible default ``false``.

New Modules
-----------

- instance - Manages server instances on Vultr.

v1.0.1
======

Minor Changes
-------------

- Improved documentation and removed unused code.

v1.0.0
======

New Modules
-----------

- account_info - Get information about the Vultr account.
- block_storage - Manages block storage volumes on Vultr.
- block_storage_info - Get information about the Vultr block storage available.
- dns_domain - Manages DNS domains on Vultr.
- dns_domain_info - Gather information about the Vultr DNS domains available.
- dns_record - Manages DNS records on Vultr.
- firewall_group - Manages firewall groups on Vultr.
- firewall_group_info - Gather information about the Vultr firewall groups available.
- firewall_rule - Manages firewall rules on Vultr.
- firewall_rule_info - Gather information about the Vultr firewall rules available.
- network - Manages networks on Vultr.
- network_info - Gather information about the Vultr networks available.
- os_info - Get information about the Vultr OSes available.
- plan_info - Gather information about the Vultr plans available.
- plan_metal_info - Gather information about the Vultr bare metal plans available.
- region_info - Gather information about the Vultr regions available.
- reserved_ip - Manages reserved IPs on Vultr.
- ssh_key - Manages ssh keys on Vultr.
- ssh_key_info - Get information about the Vultr SSH keys available.
- startup_script - Manages startup scripts on Vultr.
- startup_script_info - Gather information about the Vultr startup scripts available.
- user - Manages users on Vultr.
- user_info - Get information about the Vultr user available.
- vpc - Manages VPCs on Vultr.
- vpc_info - Gather information about the Vultr vpcs available.

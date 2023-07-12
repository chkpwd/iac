=========================================
NetApp ElementSW Collection Release Notes
=========================================

.. contents:: Topics


v21.7.0
=======

Minor Changes
-------------

- PR1 - allow usage of Ansible module group defaults - for Ansible 2.12+.

v21.6.1
=======

Bugfixes
--------

- requirements.txt - point to the correct python dependency

v21.3.0
=======

Minor Changes
-------------

- na_elementsw_info - add ``cluster_nodes`` and ``cluster_drives``.
- na_elementsw_qos_policy - explicitly define ``minIOPS``, ``maxIOPS``, ``burstIOPS`` as int.

Bugfixes
--------

- na_elementsw_drive - lastest SDK does not accept ``force_during_bin_sync`` and ``force_during_upgrade``.
- na_elementsw_qos_policy - loop would convert `minIOPS`, `maxIOPS`, `burstIOPS` to str, causing type mismatch issues in comparisons.
- na_elementsw_snapshot_schedule - change of interface in SDK ('ScheduleInfo' object has no attribute 'minutes')

v20.11.0
========

Minor Changes
-------------

- na_elementsw_snapshot_schedule - Add ``retention`` in examples.

Bugfixes
--------

- na_elementsw_drive - Object of type 'dict_values' is not JSON serializable.

v20.10.0
========

Minor Changes
-------------

- na_elementsw_cluster - add new options ``encryption``, ``order_number``, and ``serial_number``.
- na_elementsw_network_interfaces - make all options not required, so that only bond_1g can be set for example.
- na_elementsw_network_interfaces - restructure options into 2 dictionaries ``bond_1g`` and ``bond_10g``, so that there is no shared option.  Disallow all older options.

New Modules
-----------

- netapp.elementsw.na_elementsw_info - NetApp Element Software Info

v20.9.1
=======

Bugfixes
--------

- na_elementsw_node - improve error reporting when cluster name cannot be set because node is already active.
- na_elementsw_schedule - missing imports TimeIntervalFrequency, Schedule, ScheduleInfo have been added back

v20.9.0
=======

Minor Changes
-------------

- na_elementsw_node - ``cluster_name`` to set the cluster name on new nodes.
- na_elementsw_node - ``preset_only`` to only set the cluster name before creating a cluster with na_elementsw_cluster.
- na_elementsw_volume - ``qos_policy_name`` to provide a QOS policy name or ID.

Bugfixes
--------

- na_elementsw_node - fix check_mode so that no action is taken.

New Modules
-----------

- netapp.elementsw.na_elementsw_qos_policy - NetApp Element Software create/modify/rename/delete QOS Policy

v20.8.0
=======

Minor Changes
-------------

- add "required:true" where missing.
- add "type:str" (or int, dict) where missing in documentation section.
- na_elementsw_drive - add all drives in a cluster, allow for a list of nodes or a list of drives.
- remove "required:true" for state and use present as default.
- use a three group format for ``version_added``.  So 2.7 becomes 2.7.0.  Same thing for 2.8 and 2.9.

Bugfixes
--------

- na_elementsw_access_group - fix check_mode so that no action is taken.
- na_elementsw_admin_users - fix check_mode so that no action is taken.
- na_elementsw_cluster - create cluster if it does not exist.  Do not expect MVIP or SVIP to exist before create.
- na_elementsw_cluster_snmp - double exception because of AttributeError.
- na_elementsw_drive - node_id or drive_id were not handled properly when using numeric ids.
- na_elementsw_initiators - volume_access_group_id was ignored.  volume_access_groups was ignored and redundant.
- na_elementsw_ldap - double exception because of AttributeError.
- na_elementsw_snapshot_schedule - ignore schedules being deleted (idempotency), remove default values and fix documentation.
- na_elementsw_vlan - AttributeError if VLAN already exists.
- na_elementsw_vlan - change in attributes was ignored.
- na_elementsw_vlan - fix check_mode so that no action is taken.
- na_elementsw_volume - Argument '512emulation' in argument_spec is not a valid python identifier - renamed to enable512emulation.
- na_elementsw_volume - double exception because of AttributeError.

v20.6.0
=======

Bugfixes
--------

- galaxy.yml - fix repository and homepage links.

v20.2.0
=======

Bugfixes
--------

- galaxy.yml - fix path to github repository.
- netapp.py - report error in case of connection error rather than raising a generic exception by default.

v20.1.0
=======

New Modules
-----------

- netapp.elementsw.na_elementsw_access_group_volumes - NetApp Element Software Add/Remove Volumes to/from Access Group

v19.10.0
========

Minor Changes
-------------

- refactor existing modules as a collection

v2.8.0
======

New Modules
-----------

- netapp.elementsw.na_elementsw_cluster_config - Configure Element SW Cluster
- netapp.elementsw.na_elementsw_cluster_snmp - Configure Element SW Cluster SNMP
- netapp.elementsw.na_elementsw_initiators - Manage Element SW initiators

v2.7.0
======

New Modules
-----------

- netapp.elementsw.na_elementsw_access_group - NetApp Element Software Manage Access Groups
- netapp.elementsw.na_elementsw_account - NetApp Element Software Manage Accounts
- netapp.elementsw.na_elementsw_admin_users - NetApp Element Software Manage Admin Users
- netapp.elementsw.na_elementsw_backup - NetApp Element Software Create Backups
- netapp.elementsw.na_elementsw_check_connections - NetApp Element Software Check connectivity to MVIP and SVIP.
- netapp.elementsw.na_elementsw_cluster - NetApp Element Software Create Cluster
- netapp.elementsw.na_elementsw_cluster_pair - NetApp Element Software Manage Cluster Pair
- netapp.elementsw.na_elementsw_drive - NetApp Element Software Manage Node Drives
- netapp.elementsw.na_elementsw_ldap - NetApp Element Software Manage ldap admin users
- netapp.elementsw.na_elementsw_network_interfaces - NetApp Element Software Configure Node Network Interfaces
- netapp.elementsw.na_elementsw_node - NetApp Element Software Node Operation
- netapp.elementsw.na_elementsw_snapshot - NetApp Element Software Manage Snapshots
- netapp.elementsw.na_elementsw_snapshot_restore - NetApp Element Software Restore Snapshot
- netapp.elementsw.na_elementsw_snapshot_schedule - NetApp Element Software Snapshot Schedules
- netapp.elementsw.na_elementsw_vlan - NetApp Element Software Manage VLAN
- netapp.elementsw.na_elementsw_volume - NetApp Element Software Manage Volumes
- netapp.elementsw.na_elementsw_volume_clone - NetApp Element Software Create Volume Clone
- netapp.elementsw.na_elementsw_volume_pair - NetApp Element Software Volume Pair

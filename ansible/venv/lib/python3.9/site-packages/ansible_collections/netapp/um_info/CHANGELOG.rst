====================================================
NetApp Unified Manager Info Collection Release Notes
====================================================

.. contents:: Topics


v21.8.0
=======

Minor Changes
-------------

- PR1 - allow usage of Ansible module group defaults - for Ansible 2.12+.

v21.7.0
=======

Minor Changes
-------------

- all modules - ability to trace API calls and responses.
- all modules - new ``max_records`` option to limit the amount of data in a single GET response.

Bugfixes
--------

- all modules - report error when connecting to a server that does not run AIQUM.
- all modules - return all records rather than the first 1000 records (mostly for volumes).
- rename na_um_list_volumes.p to na_um_list_volumes.py

v21.6.0
=======

Minor Changes
-------------

- na_um_list_aggregates has been renamed na_um_aggregates_info.
- na_um_list_clusters has been renamed na_um_clusters_info.
- na_um_list_nodes has been renamed na_um_nodes_info.
- na_um_list_svms has been renamed na_um_svms_info.
- na_um_list_volumes has been renamed na_um_volumes_info.

v21.5.0
=======

Minor Changes
-------------

- minor changes to meet Red Hat requirements to be certified.

v20.7.0
=======

Minor Changes
-------------

- na_um_list_aggregates - Now sort by performance_capacity.used
- na_um_list_nodes - Now sort by performance_capacity.used

v20.6.0
=======

New Modules
-----------

- netapp.um_info.na_um_list_volumes - NetApp Unified Manager list volumes.

v20.5.0
=======

New Modules
-----------

- netapp.um_info.na_um_list_aggregates - NetApp Unified Manager list aggregates.
- netapp.um_info.na_um_list_clusters - NetApp Unified Manager list cluster.
- netapp.um_info.na_um_list_nodes - NetApp Unified Manager list nodes.
- netapp.um_info.na_um_list_svms - NetApp Unified Manager list svms.

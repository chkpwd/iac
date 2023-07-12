===========================
Community SAP Release Notes
===========================

.. contents:: Topics


v1.0.0
======

Release Summary
---------------

This is the fir major release of the ``community.sap`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Minor Changes
-------------

- sapcar_extract.py - more strict logic for filenames

New Modules
-----------

Identity
~~~~~~~~

- identity.sap_company - This module will manage a company entities in a SAP S4HANA environment
- identity.sap_user - This module will manage a user entities in a SAP S4/HANA environment

System
~~~~~~

- system.sap_snote - This module will upload and (de)implements C(SNOTES) in a SAP S4HANA environment.
- system.sap_system_facts - Gathers SAP facts in a host

v0.1.0
======

Release Summary
---------------

This is the minor release of the ``community.sap`` collection. It is the initial relase for the ``community.sap`` collection

New Modules
-----------

Database
~~~~~~~~

saphana
^^^^^^^

- database.saphana.hana_query - Execute SQL on HANA

Files
~~~~~

- files.sapcar_extract - Manages SAP SAPCAR archives

System
~~~~~~

- system.sap_task_list_execute - Perform SAP Task list execution

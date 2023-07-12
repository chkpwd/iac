===========================================
T_Systems_Mms.Icinga_Director Release Notes
===========================================

.. contents:: Topics


v1.33.1
=======

Bugfixes
--------

- add icinga_deploy_* to action_group and test it (https://github.com/T-Systems-MMS/ansible-collection-icinga-director/pull/214)

v1.33.0
=======

Minor Changes
-------------

- Add Icinga Deploy handler and module (https://github.com/T-Systems-MMS/ansible-collection-icinga-director/pull/205)

New Modules
-----------

- t_systems_mms.icinga_director.icinga_deploy - Trigger deployment in Icinga2
- t_systems_mms.icinga_director.icinga_deploy_info - Get deployment information through the director API

v1.32.3
=======

v1.32.2
=======

v1.32.1
=======

v1.32.0
=======

Minor Changes
-------------

- Add zone to user and notification template (https://github.com/T-Systems-MMS/ansible-collection-icinga-director/pull/198)

v1.31.5
=======

v1.31.4
=======

v1.31.3
=======

v1.31.2
=======

v1.31.1
=======

v1.31.0
=======

Minor Changes
-------------

- Add flapping support to service template module (https://github.com/T-Systems-MMS/ansible-collection-icinga-director/pull/180)
- Add icon support to service template (https://github.com/T-Systems-MMS/ansible-collection-icinga-director/pull/179)

v1.30.2
=======

v1.30.1
=======

Bugfixes
--------

- Add exception handling to diff and exist functions (https://github.com/T-Systems-MMS/ansible-collection-icinga-director/pull/176)

v1.30.0
=======

Minor Changes
-------------

- Add action_group to enable module default groups (https://github.com/T-Systems-MMS/ansible-collection-icinga-director/pull/175)

v1.29.1
=======

v1.29.0
=======

Minor Changes
-------------

- Add icinga_serviceset module (https://github.com/T-Systems-MMS/ansible-collection-icinga-director/pull/163)
- Test more ansible versions (https://github.com/T-Systems-MMS/ansible-collection-icinga-director/pull/162)

New Modules
-----------

- t_systems_mms.icinga_director.icinga_serviceset - Manage servicesets in Icinga2

v1.28.1
=======

Minor Changes
-------------

- Test more ansible versions (https://github.com/T-Systems-MMS/ansible-collection-icinga-director/pull/162)

v1.28.0
=======

Minor Changes
-------------

- Added missing fields to 'icinga_host' and 'icinga_host_template' (https://github.com/T-Systems-MMS/ansible-collection-icinga-director/pull/158)

Bugfixes
--------

- role: add check_command to icinga_service_apply (https://github.com/T-Systems-MMS/ansible-collection-icinga-director/pull/161)

v1.27.2
=======

v1.27.1
=======

v1.27.0
=======

Minor Changes
-------------

- Add possibility to use Compose and keyed groups in inventory-module (https://github.com/T-Systems-MMS/ansible-collection-icinga-director/pull/155)

v1.26.0
=======

Minor Changes
-------------

- add option to append arguments to all modules (https://github.com/T-Systems-MMS/ansible-collection-icinga-director/pull/153)

v1.25.1
=======

v1.25.0
=======

Minor Changes
-------------

- Add Icinga scheduled downtime module (https://github.com/T-Systems-MMS/ansible-collection-icinga-director/pull/146)

Bugfixes
--------

- added a fix for the new scheduled_downtime module (https://github.com/T-Systems-MMS/ansible-collection-icinga-director/pull/150)

v1.23.1
=======

Minor Changes
-------------

- add resolve option to inventory-plugin (https://github.com/T-Systems-MMS/ansible-collection-icinga-director/pull/147)

v1.23.0
=======

v1.22.1
=======

v1.22.0
=======

Minor Changes
-------------

- Add support for retry_interval and max_check_attempts to host template (https://github.com/T-Systems-MMS/ansible-collection-icinga-director/pull/140)

v1.21.2
=======

v1.21.1
=======

Bugfixes
--------

- Changed place in the creation order of service object in ansible_icinga role (https://github.com/T-Systems-MMS/ansible-collection-icinga-director/pull/135)

v1.21.0
=======

Minor Changes
-------------

- Add event_command parameter to icinga_service_apply module (https://github.com/T-Systems-MMS/ansible-collection-icinga-director/pull/132)
- Add event_command parameter to service apply playbook to enable usage (https://github.com/T-Systems-MMS/ansible-collection-icinga-director/pull/133)

v1.20.1
=======

v1.20.0
=======

Minor Changes
-------------

- Add some more documentation on command template (https://github.com/T-Systems-MMS/ansible-collection-icinga-director/pull/128)
- add "vars" variable to icinga_notification in the role (https://github.com/T-Systems-MMS/ansible-collection-icinga-director/pull/129)

v1.19.0
=======

Minor Changes
-------------

- add notification_template to role (https://github.com/T-Systems-MMS/ansible-collection-icinga-director/pull/125)

v1.18.1
=======

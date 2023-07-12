==============================
Vultr Collection Release Notes
==============================

.. contents:: Topics


v1.1.3
======

Bugfixes
--------

- iventory - Fixed ``allowed_bandwidth_gb`` to be returned as float (https://github.com/ngine-io/ansible-collection-vultr/pull/35).
- vultr_server - Fixed ``allowed_bandwidth_gb`` to be returned as float (https://github.com/ngine-io/ansible-collection-vultr/pull/35).
- vultr_server_baremetal - Fixed ``allowed_bandwidth_gb`` to be returned as float (https://github.com/ngine-io/ansible-collection-vultr/pull/35).

v1.1.2
======

Release Summary
---------------

This collection has turned into maintenance mode. We encourage you to add new features to its successor at https://galaxy.ansible.com/vultr/cloud.


Minor Changes
-------------

- Documentation fixes.

v1.1.1
======

Bugfixes
--------

- vultr_server - Fix user data not handled correctly (https://github.com/ngine-io/ansible-collection-vultr/pull/26).

v1.1.0
======

Minor Changes
-------------

- vultr_block_storage - Included ability to resize, attach and detach Block Storage Volumes.

v1.0.0
======

v0.3.0
======

Minor Changes
-------------

- vultr_server_info, vultr_server - Improved handling of discontinued plans (https://github.com/ansible/ansible/issues/66707).

Bugfixes
--------

- vultr - Fixed the issue retry max delay param was ignored.

New Modules
-----------

- vultr_plan_baremetal_info - Gather information about the Vultr Bare Metal plans available.
- vultr_server_baremetal - Manages baremetal servers on Vultr.

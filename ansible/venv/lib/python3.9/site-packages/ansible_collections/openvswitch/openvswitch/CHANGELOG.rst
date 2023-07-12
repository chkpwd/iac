====================================
Openvswitch Collection Release Notes
====================================

.. contents:: Topics


v2.1.1
======

Bugfixes
--------

- Fix galaxy version issue when installing this collection.

Documentation Changes
---------------------

- Update module documentation and examples.

v2.1.0
======

Minor Changes
-------------

- Allows read operation in openvswitch_db module(https://github.com/ansible-collections/openvswitch.openvswitch/pull/88)
- openvswitch modules got support for database socket parameter.

v2.0.2
======

Bugfixes
--------

- `openvswitch_bridge` - Fix idempotency for VLAN bridges

v2.0.1
======

Major Changes
-------------

- By mistake we tagged the repo to 2.0.0 and as it wasn't intended and cannot be reverted we're releasing 2.0.1 to make the community aware of the major version update.

v2.0.0
======

Major Changes
-------------

- There is no major changes for this particular release and it was tagged by mistake and cannot be reverted.

v1.2.0
======

Minor Changes
-------------

- Allow setting multiple properties on a port (https://github.com/ansible-collections/openvswitch.openvswitch/issues/63).

Bugfixes
--------

- Allow deleting key from table without specifying value (https://github.com/ansible-collections/openvswitch.openvswitch/issues/64).

v1.1.0
======

Minor Changes
-------------

- openvswitch_bond - New module for managing Open vSwitch bonds (https://github.com/ansible-collections/openvswitch.openvswitch/pull/58).

Bugfixes
--------

- Add version key to galaxy.yaml to work around ansible-galaxy bug (https://github.com/ansible-collections/openvswitch.openvswitch/issues/59)

v1.0.5
======

Minor Changes
-------------

- Regenerated docs, add description to galaxy.yml and linked changelog to README (https://github.com/ansible-collections/openvswitch.openvswitch/pull/53).

v1.0.4
======

Release Summary
---------------

Rereleased 1.0.3 with updated changelog.

v1.0.3
======

Release Summary
---------------

Released for testing.

v1.0.2
======

Release Summary
---------------

Rereleased 1.0.1 with updated changelog.

v1.0.1
======

Bugfixes
--------

- Makes sure that docstring and argspec are in sync and removes sanity ignores (https://github.com/ansible-collections/openvswitch.openvswitch/pull/46).
- Update docs after sanity fixes to modules.

v1.0.0
======

New Modules
-----------

- openvswitch_bridge - Manage Open vSwitch bridges
- openvswitch_db - Configure open vswitch database.
- openvswitch_port - Manage Open vSwitch ports

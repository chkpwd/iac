================================================
Ansible Microsoft Active Directory Release Notes
================================================

.. contents:: Topics


v1.2.0
======

Release Summary
---------------

Release summary for v1.2.0

Minor Changes
-------------

- microsoft.ad.debug_ldap_client - Add ``dpapi_ng`` to list of packages checked
- microsoft.ad.ldap - Add support for decrypting LAPS encrypted password
- microsoft.ad.ldap - Allow setting LDAP connection and authentication options through environment variables - https://github.com/ansible-collections/microsoft.ad/issues/34

Deprecated Features
-------------------

- Deprecating support for Server 2012 and Server 2012 R2. These OS versions are reaching End of Life status from Microsoft and support for using them in Ansible are nearing its end.

Bugfixes
--------

- group - Fix idempotency check when ``scope: domainlocal`` is set - https://github.com/ansible-collections/microsoft.ad/issues/31
- microsoft.ad.group - ensure the ``scope`` and ``category`` values are checked as case insensitive to avoid changes when not needed - https://github.com/ansible-collections/microsoft.ad/issues/31

v1.1.0
======

Release Summary
---------------

This release includes the new ``microsoft.ad.ldap`` inventory plugin which can be used to generate an Ansible
inventory from an LDAP/AD source.


Bugfixes
--------

- microsoft.ad.user - Fix setting ``password_expired`` when creating a new user - https://github.com/ansible-collections/microsoft.ad/issues/25

New Plugins
-----------

Filter
~~~~~~

- as_datetime - Converts an LDAP value to a datetime string
- as_guid - Converts an LDAP value to a GUID string
- as_sid - Converts an LDAP value to a Security Identifier string

Inventory
~~~~~~~~~

- ldap - Inventory plugin for Active Directory

New Modules
-----------

- debug_ldap_client - Get host information for debugging LDAP connections

v1.0.0
======

Release Summary
---------------

This is the first release of the ``microsoft.ad`` Ansible collection which contains modules that can be used to managed a Microsoft Active Directory environment.

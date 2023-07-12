======================================
Community DNS Collection Release Notes
======================================

.. contents:: Topics


v2.5.6
======

Release Summary
---------------

Maintenance release.

From this version on, community.dns is using the new `Ansible semantic markup
<https://docs.ansible.com/ansible/devel/dev_guide/developing_modules_documenting.html#semantic-markup-within-module-documentation>`__
in its documentation. If you look at documentation with the ansible-doc CLI tool
from ansible-core before 2.15, please note that it does not render the markup
correctly. You should be still able to read it in most cases, but you need
ansible-core 2.15 or later to see it as it is intended. Alternatively you can
look at `the devel docsite <https://docs.ansible.com/ansible/devel/collections/community/dns/>`__
for the rendered HTML version of the documentation of the latest release.


Known Issues
------------

- Ansible markup will show up in raw form on ansible-doc text output for ansible-core before 2.15. If you have trouble deciphering the documentation markup, please upgrade to ansible-core 2.15 (or newer), or read the HTML documentation on https://docs.ansible.com/ansible/devel/collections/community/dns/.

v2.5.5
======

Release Summary
---------------

Maintenance release with updated PSL.

Bugfixes
--------

- Update Public Suffix List.

v2.5.4
======

Release Summary
---------------

Maintenance release with updated PSL.

Bugfixes
--------

- Update Public Suffix List.

v2.5.3
======

Release Summary
---------------

Maintenance release with updated PSL.

Bugfixes
--------

- Update Public Suffix List.

v2.5.2
======

Release Summary
---------------

Maintenance release with improved documentation and updated PSL.

Bugfixes
--------

- Update Public Suffix List.

v2.5.1
======

Release Summary
---------------

Maintenance release (updated PSL).

Bugfixes
--------

- Update Public Suffix List.

v2.5.0
======

Release Summary
---------------

Feature and bugfix release with updated PSL.

Minor Changes
-------------

- hosttech inventory plugin - allow to configure token, username, and password with ``ANSIBLE_HOSTTECH_DNS_TOKEN``, ``ANSIBLE_HOSTTECH_API_USERNAME``, and ``ANSIBLE_HOSTTECH_API_PASSWORD`` environment variables, respectively (https://github.com/ansible-collections/community.dns/pull/131).
- various modules and inventory plugins - add new option ``txt_character_encoding`` which controls whether numeric escape sequences are interpreted as octals or decimals when ``txt_transformation=quoted`` (https://github.com/ansible-collections/community.dns/pull/134).

Deprecated Features
-------------------

- The default of the newly added option ``txt_character_encoding`` will change from ``octal`` to ``decimal`` in community.dns 3.0.0. The new default will be compatible with `RFC 1035 <https://www.ietf.org/rfc/rfc1035.txt>`__ (https://github.com/ansible-collections/community.dns/pull/134).

Bugfixes
--------

- Update Public Suffix List.
- inventory plugins - document ``plugin`` option used by the ``ansible.builtin.auto`` inventory plugin and mention required file ending in the documentation (https://github.com/ansible-collections/community.dns/issues/130, https://github.com/ansible-collections/community.dns/pull/131).

v2.4.2
======

Release Summary
---------------

Maintenance release with updated Public Suffix List.

Bugfixes
--------

- Update Public Suffix List.

v2.4.1
======

Release Summary
---------------

Regular maintenance release.

Bugfixes
--------

- Update Public Suffix List.
- wait_for_txt - also retrieve IPv6 addresses of nameservers. Prevents failures with IPv6 only nameservers (https://github.com/ansible-collections/community.dns/issues/120, https://github.com/ansible-collections/community.dns/pull/121).

v2.4.0
======

Release Summary
---------------

Feature and maintenance release.

Minor Changes
-------------

- Added a ``community.dns.hetzner`` module defaults group / action group. Use with ``group/community.dns.hetzner`` to provide options for all Hetzner DNS modules (https://github.com/ansible-collections/community.dns/pull/119).
- Added a ``community.dns.hosttech`` module defaults group / action group. Use with ``group/community.dns.hosttech`` to provide options for all Hosttech DNS modules (https://github.com/ansible-collections/community.dns/pull/119).
- wait_for_txt - the module now supports check mode. The only practical change in behavior is that in check mode, the module is now executed instead of skipped. Since the module does not change anything, it should have been marked as supporting check mode since it was originally added (https://github.com/ansible-collections/community.dns/pull/119).

Bugfixes
--------

- Update Public Suffix List.

v2.3.4
======

Release Summary
---------------

Maintenance release with updated Public Suffix List.

Bugfixes
--------

- Update Public Suffix List.

v2.3.3
======

Release Summary
---------------

Maintenance release including an updated Public Suffix List.

Bugfixes
--------

- Update Public Suffix List.

v2.3.2
======

Release Summary
---------------

Maintenance release with updated Public Suffix List.

Bugfixes
--------

- Update Public Suffix List.

v2.3.1
======

Release Summary
---------------

Maintenance release including an updated Public Suffix List.

Minor Changes
-------------

- The collection repository conforms to the `REUSE specification <https://reuse.software/spec/>`__ except for the changelog fragments (https://github.com/ansible-collections/community.dns/pull/112).

Bugfixes
--------

- Update Public Suffix List.

v2.3.0
======

Release Summary
---------------

Maintenance release including an updated Public Suffix List.

Minor Changes
-------------

- All software licenses are now in the ``LICENSES/`` directory of the collection root. Moreover, ``SPDX-License-Identifier:`` is used to declare the applicable license for every file that is not automatically generated (https://github.com/ansible-collections/community.dns/pull/109).

Bugfixes
--------

- Update Public Suffix List.

v2.2.1
======

Release Summary
---------------

Maintenance release with updated Public Suffix List.

Bugfixes
--------

- Update Public Suffix List.

v2.2.0
======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- hetzner_dns_records and hosttech_dns_records inventory plugins - allow to template provider-specific credentials and the ``zone_name``, ``zone_id`` options (https://github.com/ansible-collections/community.dns/pull/106).
- wait_for_txt - improve error messages so that in case of SERVFAILs or other DNS errors it is clear which record was queried from which DNS server (https://github.com/ansible-collections/community.dns/pull/105).

Bugfixes
--------

- Update Public Suffix List.

v2.1.1
======

Release Summary
---------------

Maintenance release with updated Public Suffix List.

Bugfixes
--------

- Update Public Suffix List.

v2.1.0
======

Release Summary
---------------

Feature and maintenance release with updated PSL.

Minor Changes
-------------

- Prepare collection for inclusion in an Execution Environment by declaring its dependencies (https://github.com/ansible-collections/community.dns/pull/93).

Bugfixes
--------

- Update Public Suffix List.

v2.0.9
======

Release Summary
---------------

Maintenance release with updated Public Suffix List and added collection links file.

Bugfixes
--------

- Update Public Suffix List.

v2.0.8
======

Release Summary
---------------

Maintenance release with updated Public Suffix List.

Bugfixes
--------

- Update Public Suffix List.

v2.0.7
======

Release Summary
---------------

Maintenance release with updated Public Suffix List.

Bugfixes
--------

- Update Public Suffix List.

v2.0.6
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- Update Public Suffix List.
- wait_for_txt - do not fail if ``NXDOMAIN`` result is returned. Also do not succeed if no nameserver can be found (https://github.com/ansible-collections/community.dns/issues/81, https://github.com/ansible-collections/community.dns/pull/82).

v2.0.5
======

Release Summary
---------------

Maintenance release with updated Public Suffix List.

Bugfixes
--------

- Update Public Suffix List.

v2.0.4
======

Release Summary
---------------

Maintenance release with updated Public Suffix List.

Bugfixes
--------

- Update Public Suffix List.

v2.0.3
======

Release Summary
---------------

Bugfix release.

Minor Changes
-------------

- HTTP API module utils - fix usage of ``fetch_url`` with changes in latest ansible-core ``devel`` branch (https://github.com/ansible-collections/community.dns/pull/73).

v2.0.2
======

Release Summary
---------------

Regular maintenance release.

Bugfixes
--------

- Update Public Suffix List.

v2.0.1
======

Release Summary
---------------

Maintenance release with Public Suffix List updates.

Bugfixes
--------

- Update Public Suffix List.

v2.0.0
======

Release Summary
---------------

This release contains many new features, modules and plugins, but also has several breaking changes to the 1.x.y versions. Please read the changelog carefully to determine what to change if you used an earlier version of this collection.

Minor Changes
-------------

- Add support for Hetzner DNS (https://github.com/ansible-collections/community.dns/pull/27).
- Added a ``txt_transformation`` option to all modules and plugins working with DNS records (https://github.com/ansible-collections/community.dns/issues/48, https://github.com/ansible-collections/community.dns/pull/57, https://github.com/ansible-collections/community.dns/pull/60).
- The hosttech_dns_records module has been renamed to hosttech_dns_record_sets (https://github.com/ansible-collections/community.dns/pull/31).
- The internal API now supports bulk DNS record changes, if supported by the API (https://github.com/ansible-collections/community.dns/pull/39).
- The internal record API allows to manage extra data (https://github.com/ansible-collections/community.dns/pull/63).
- Use HTTP helper class to make API implementations work for both plugins and modules. Make WSDL API use ``fetch_url`` instead of ``open_url`` for modules (https://github.com/ansible-collections/community.dns/pull/36).
- hetzner_dns_record and hosttech_dns_record - when not using check mode, use actual return data for diff, instead of input data, so that extra data can be shown (https://github.com/ansible-collections/community.dns/pull/63).
- hetzner_dns_zone_info - the ``legacy_ns`` return value is now sorted, since its order is unstable (https://github.com/ansible-collections/community.dns/pull/46).
- hosttech_dns_* modules - rename ``zone`` parameter to ``zone_name``. The old name ``zone`` can still be used as an alias (https://github.com/ansible-collections/community.dns/pull/32).
- hosttech_dns_record_set - ``value`` is no longer required when ``state=absent`` and ``overwrite=true`` (https://github.com/ansible-collections/community.dns/pull/31).
- hosttech_dns_record_sets - ``records`` has been renamed to ``record_sets``. The old name ``records`` can still be used as an alias (https://github.com/ansible-collections/community.dns/pull/31).
- hosttech_dns_zone_info - return extra information as ``zone_info`` (https://github.com/ansible-collections/community.dns/pull/38).

Breaking Changes / Porting Guide
--------------------------------

- All Hetzner modules and plugins which handle DNS records now work with unquoted TXT values by default. The old behavior can be obtained by setting ``txt_transformation=api`` (https://github.com/ansible-collections/community.dns/issues/48, https://github.com/ansible-collections/community.dns/pull/57, https://github.com/ansible-collections/community.dns/pull/60).
- Hosttech API creation - now requires a ``ModuleOptionProvider`` object instead of an ``AnsibleModule`` object. Alternatively an Ansible plugin instance can be passed (https://github.com/ansible-collections/community.dns/pull/37).
- The hetzner_dns_record_info and hosttech_dns_record_info modules have been renamed to hetzner_dns_record_set_info and hosttech_dns_record_set_info, respectively (https://github.com/ansible-collections/community.dns/pull/54).
- The hosttech_dns_record module has been renamed to hosttech_dns_record_set (https://github.com/ansible-collections/community.dns/pull/31).
- The internal bulk record updating helper (``bulk_apply_changes``) now also returns the records that were deleted, created or updated (https://github.com/ansible-collections/community.dns/pull/63).
- The internal record API no longer allows to manage comments explicitly (https://github.com/ansible-collections/community.dns/pull/63).
- When using the internal modules API, now a zone ID type and a provider information object must be passed (https://github.com/ansible-collections/community.dns/pull/27).
- hetzner_dns_record* modules - implement correct handling of default TTL. The value ``none`` is now accepted and returned in this case (https://github.com/ansible-collections/community.dns/pull/52, https://github.com/ansible-collections/community.dns/issues/50).
- hetzner_dns_record, hetzner_dns_record_set, hetzner_dns_record_sets - the default TTL is now 300 and no longer 3600, which equals the default in the web console (https://github.com/ansible-collections/community.dns/pull/43).
- hosttech_dns_record_set - the option ``overwrite`` was replaced by a new option ``on_existing``. Specifying ``overwrite=true`` is equivalent to ``on_existing=replace`` (the new default). Specifying ``overwrite=false`` with ``state=present`` is equivalent to ``on_existing=keep_and_fail``, and specifying ``overwrite=false`` with ``state=absent`` is equivalent to ``on_existing=keep`` (https://github.com/ansible-collections/community.dns/pull/31).

Deprecated Features
-------------------

- The hosttech_dns_records module has been renamed to hosttech_dns_record_sets. The old name will stop working in community.dns 3.0.0 (https://github.com/ansible-collections/community.dns/pull/31).

Bugfixes
--------

- Hetzner API - interpret missing TTL as 300, which is what the web console also does (https://github.com/ansible-collections/community.dns/pull/42).
- Update Public Suffix List.
- Update Public Suffix List.
- Update Public Suffix List.
- hetzner API code - make sure to also handle errors returned by the API if the HTTP status code indicates success. This sometimes happens for 500 Internal Server Error (https://github.com/ansible-collections/community.dns/pull/58).
- hosttech_dns_zone_info - make sure that full information is returned both when requesting a zone by ID or by name (https://github.com/ansible-collections/community.dns/pull/56).
- wait_for_txt - fix handling of too long TXT values (https://github.com/ansible-collections/community.dns/pull/65).
- wait_for_txt - resolving nameservers sometimes resulted in an empty list, yielding wrong results (https://github.com/ansible-collections/community.dns/pull/64).

New Plugins
-----------

Inventory
~~~~~~~~~

- community.dns.hetzner_dns_records - Create inventory from Hetzner DNS records
- community.dns.hosttech_dns_records - Create inventory from Hosttech DNS records

New Modules
-----------

- community.dns.hetzner_dns_record - Add or delete a single record in Hetzner DNS service
- community.dns.hetzner_dns_record_info - Retrieve records in Hetzner DNS service
- community.dns.hetzner_dns_record_set - Add or delete record sets in Hetzner DNS service
- community.dns.hetzner_dns_record_set_info - Retrieve record sets in Hetzner DNS service
- community.dns.hetzner_dns_record_sets - Bulk synchronize DNS record sets in Hetzner DNS service
- community.dns.hetzner_dns_zone_info - Retrieve zone information in Hetzner DNS service
- community.dns.hosttech_dns_record - Add or delete a single record in Hosttech DNS service
- community.dns.hosttech_dns_record_info - Retrieve records in Hosttech DNS service
- community.dns.hosttech_dns_record_set - Add or delete record sets in Hosttech DNS service
- community.dns.hosttech_dns_record_sets - Bulk synchronize DNS record sets in Hosttech DNS service

v1.2.0
======

Release Summary
---------------

Last minor 1.x.0 version. The 2.0.0 version will have some backwards incompatible changes to the ``hosttech_dns_record`` and ``hosttech_dns_records`` modules which will require user intervention. These changes should result in a better UX.


Minor Changes
-------------

- hosttech modules - add ``api_token`` alias for ``hosttech_token`` (https://github.com/ansible-collections/community.dns/pull/26).
- hosttech_dns_record - in ``diff`` mode, also return ``diff`` data structure when ``changed`` is ``false`` (https://github.com/ansible-collections/community.dns/pull/28).
- module utils - add default implementation for some zone/record API functions, and move common JSON API code to helper class (https://github.com/ansible-collections/community.dns/pull/26).

Bugfixes
--------

- Update Public Suffix List.
- hosttech_dns_record - correctly handle quoting in CAA records for JSON API (https://github.com/ansible-collections/community.dns/pull/30).

v1.1.0
======

Release Summary
---------------

Regular maintenance release.

Minor Changes
-------------

- Avoid internal ansible-core module_utils in favor of equivalent public API available since at least Ansible 2.9 (https://github.com/ansible-collections/community.dns/pull/24).

Bugfixes
--------

- Update Public Suffix List.

v1.0.1
======

Release Summary
---------------

Regular maintenance release.

Bugfixes
--------

- Update Public Suffix List.

v1.0.0
======

Release Summary
---------------

First stable release.

Bugfixes
--------

- Update Public Suffix List.

v0.3.0
======

Release Summary
---------------

Fixes bugs, adds rate limiting for Hosttech JSON API, and adds a new bulk synchronization module.

Minor Changes
-------------

- hosttech_dns_* - handle ``419 Too Many Requests`` with proper rate limiting for JSON API (https://github.com/ansible-collections/community.dns/pull/14).

Bugfixes
--------

- Avoid converting ASCII labels which contain underscores or other printable ASCII characters outside ``[a-zA-Z0-9-]`` to alabels during normalization (https://github.com/ansible-collections/community.dns/pull/13).
- Updated Public Suffix List.

New Modules
-----------

- community.dns.hosttech_dns_records - Bulk synchronize DNS records in Hosttech DNS service

v0.2.0
======

Release Summary
---------------

Major refactoring release, which adds a zone information module and supports HostTech's new REST API.

Major Changes
-------------

- hosttech_* modules - support the new JSON API at https://api.ns1.hosttech.eu/api/documentation/ (https://github.com/ansible-collections/community.dns/pull/4).

Minor Changes
-------------

- hosttech_dns_record* modules - allow to specify ``prefix`` instead of ``record`` (https://github.com/ansible-collections/community.dns/pull/8).
- hosttech_dns_record* modules - allow to specify zone by ID with the ``zone_id`` parameter, alternatively to the ``zone`` parameter (https://github.com/ansible-collections/community.dns/pull/7).
- hosttech_dns_record* modules - return ``zone_id`` on success (https://github.com/ansible-collections/community.dns/pull/7).
- hosttech_dns_record* modules - support IDN domain names and prefixes (https://github.com/ansible-collections/community.dns/pull/9).
- hosttech_dns_record_info - also return ``prefix`` for a record set (https://github.com/ansible-collections/community.dns/pull/8).
- hosttech_record - allow to delete records without querying their content first by specifying ``overwrite=true`` (https://github.com/ansible-collections/community.dns/pull/4).

Breaking Changes / Porting Guide
--------------------------------

- hosttech_* module_utils - completely rewrite and refactor to support new JSON API and allow to re-use provider-independent module logic (https://github.com/ansible-collections/community.dns/pull/4).

Bugfixes
--------

- Update Public Suffix List.
- hosttech_record - fix diff mode for ``state=absent`` (https://github.com/ansible-collections/community.dns/pull/4).
- hosttech_record_info - fix authentication error handling (https://github.com/ansible-collections/community.dns/pull/4).

New Modules
-----------

- community.dns.hosttech_dns_zone_info - Retrieve zone information in Hosttech DNS service

v0.1.0
======

Release Summary
---------------

Initial public release.

New Plugins
-----------

Filter
~~~~~~

- community.dns.get_public_suffix - Returns the public suffix of a DNS name
- community.dns.get_registrable_domain - Returns the registrable domain name of a DNS name
- community.dns.remove_public_suffix - Removes the public suffix from a DNS name
- community.dns.remove_registrable_domain - Removes the registrable domain name from a DNS name

New Modules
-----------

- community.dns.hosttech_dns_record - Add or delete entries in Hosttech DNS service
- community.dns.hosttech_dns_record_info - Retrieve entries in Hosttech DNS service
- community.dns.wait_for_txt - Wait for TXT entries to be available on all authoritative nameservers

======================================
Ansible Utils Collection Release Notes
======================================

.. contents:: Topics


v2.10.3
=======

v2.10.2
=======

Minor Changes
-------------

- validate - Add option `check_format` for the jsonschema engine to disable JSON Schema format checking.
- validate - Add support for JSON Schema draft 2019-09 and 2020-12 as well as automatically choosing the draft from the `$schema` field of the criteria.

v2.10.1
=======

v2.10.0
=======

v2.9.0
======

Minor Changes
-------------

- to_xml - Added support to disable xml declartion with full_document flag.

Bugfixes
--------

- mac - reorganize regexes to work around 3.11 regex changes. (https://github.com/ansible-collections/ansible.utils/pull/231)

v2.8.0
======

Minor Changes
-------------

- to_xml - Added support for using spaces to indent an XML doc via a new `indent` parameter.

Bugfixes
--------

- Accept int input for ipaddr filters.

v2.7.0
======

Minor Changes
-------------

- Add support for content template parser
- Added new connection base class similar to ansible.netcommon's NetworkConnectionBase without the network-specific option masking (https://github.com/ansible-collections/ansible.utils/pull/213).
- ipsubnet - the index parameter should only ever be an integer if it is provided. this changes the argument type from str to int.

Bugfixes
--------

- Fix filters to only raise AnsibleFilterError exceptions (https://github.com/ansible-collections/ansible.utils/issues/209).
- ipsubnet - interacting with large subnets could cause performance constraints. the result would be the system would appear to hang while it built out a list of all possible subnets or stepped through all possible subnets one at a time. when sending a prefix that is a supernet of the passed in network the behavior wasn't consistent. this now returns an AnsibleFilterError in that scenario across all python releases. (https://github.com/ansible-collections/ansible.utils/issues/132)

v2.6.1
======

Release Summary
---------------

Rereleased 2.6.0 with fixes for internal testing.

v2.6.0
======

Minor Changes
-------------

- 'consolidate' filter plugin added.

v2.5.2
======

Bugfixes
--------

- Fix issue in ipaddr,ipv4,ipv6,ipwrap filters.(https://github.com/ansible-collections/ansible.utils/issues/148).
- ipaddr - Add valid network for link-local (https://github.com/ansible-collections/ansible.netcommon/issues/350).
- ipaddr - Fix issue of breaking ipaddr filter with netcommon 2.6.0(https://github.com/ansible-collections/ansible.netcommon/issues/375).

v2.5.1
======

Documentation Changes
---------------------

- `in_any_network` - plugin doc fix for redundant line.

v2.5.0
======

Minor Changes
-------------

- 'keep_keys' filter plugin added.
- 'remove_keys' filter plugin added.
- 'replace_keys' filter plugin added.
- Add cli_merge ipaddr filter plugin.
- Add ip4_hex filter plugin.
- Add ipaddr filter plugin.
- Add ipmath filter plugin.
- Add ipsubnet filter plugin.
- Add ipv4 filter plugin.
- Add ipv6 filter plugin.
- Add ipwrap filter plugin.
- Add network_in_network filter plugin.
- Add network_in_usable filter plugin.
- Add next_nth_usable filter plugin.
- Add nthhost filter plugin.
- Add previous_nth_usable filter plugin.
- Add reduce_on_network filter plugin.
- Add slaac,hwaddr,mac filter plugin.
- New validate sub-plugin "config" to validate device configuration against user-defined rules (https://github.com/ansible-collections/ansible.network/issues/15).

Documentation Changes
---------------------

- Enhancement in documentation and docstring.

v2.4.3
======

Release Summary
---------------

Rereleased 2.4.2 with fix of network ee tests.

v2.4.2
======

Release Summary
---------------

Rereleased 2.4.1 with valid requirement.txt.

v2.4.1
======

Release Summary
---------------

Rereleased 2.4.0 with trivial changes.

v2.4.0
======

Minor Changes
-------------

- Add new plugin param_list_compare that generates the final param list after comparing base and provided/target param list.

Bugfixes
--------

- Update validate to use 2.11 ArgumentSpecValidator if available.

v2.3.1
======

Bugfixes
--------

- Add support for the validation of formats to the jsonschema validator.
- Improve test coverage

v2.3.0
======

Minor Changes
-------------

- Add usable_range test plugin

Bugfixes
--------

- Also include empty lists and mappings into the output dictionary (https://github.com/ansible-collections/ansible.utils/pull/58).

Documentation Changes
---------------------

- Update doc for usable_range filter plugin

v2.2.0
======

Minor Changes
-------------

- Add in_any_network, in_network, in_one_network test plugins
- Add ip, ip_address test plugins
- Add ipv4, ipv4_address, ipv4_hostmask, ipv4_netmask test plugins
- Add ipv6, ipv6_address, ipv6_ipv4_mapped, ipv6_sixtofour, ipv6_teredo test plugins
- Add loopback, mac, multicast test plugins
- Add private, public, reserved test plugins
- Add resolvable test plugins
- Add subnet_of, supernet_of, unspecified test plugins

v2.1.0
======

Minor Changes
-------------

- Add from_xml and to_xml fiter plugin (https://github.com/ansible-collections/ansible.utils/pull/56).

Bugfixes
--------

- Add missing test requirements (https://github.com/ansible-collections/ansible.utils/pull/57).

v2.0.2
======

Bugfixes
--------

- Fix cli_parse template_path read error (https://github.com/ansible-collections/ansible.utils/pull/51).
- Fix jsonschema input data format checking (https://github.com/ansible-collections/ansible.utils/pull/50).

v2.0.1
======

Bugfixes
--------

- Fix ansible.utils.cli_parse action plugin to support old cli_parse sub-plugin structure in ansible.netcommon collection.

v2.0.0
======

Breaking Changes / Porting Guide
--------------------------------

- If added custom sub plugins in your collection move from old location `plugins/<sub-plugin-name>` to the new location `plugins/sub_plugins/<sub-plugin-name>` and update the imports as required
- Move sub plugins cli_parsers, fact_diff and validate to `plugins/sub_plugins` folder
- The `cli_parsers` sub plugins folder name is changed to `cli_parse` to have consistent naming convention, that is all the cli_parse subplugins will now be in `plugins/sub_plugins/cli_parse` folder

v1.0.1
======

Minor Changes
-------------

- Move CHANGELOG.rst file under changelogs folder as required

v1.0.0
======

Minor Changes
-------------

- Add cli_parse module and plugins (https://github.com/ansible-collections/ansible.utils/pull/28)
- Added fact_diff plugin and sub plugin
- Added validate module/lookup/filter/test plugin to validate data based on given criteria

Bugfixes
--------

- linting and formatting for CI

New Plugins
-----------

Lookup
~~~~~~

- get_path - Retrieve the value in a variable using a path
- index_of - Find the indices of items in a list matching some criteria
- to_paths - Flatten a complex object into a dictionary of paths and values
- validate - Validate data with provided criteria

New Modules
-----------

- cli_parse - Parse cli output or text using a variety of parsers
- fact_diff - Find the difference between currently set facts
- update_fact - Update currently set facts
- validate - Validate data with provided criteria

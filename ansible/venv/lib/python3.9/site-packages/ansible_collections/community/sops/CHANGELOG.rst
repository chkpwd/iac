============================
Community Sops Release Notes
============================

.. contents:: Topics


v1.6.2
======

Release Summary
---------------

Maintenance release.

Bugfixes
--------

- install role - make sure that the ``pkg_mgr`` fact is definitely available when installing on ``localhost``. This can improve error messages in some cases (https://github.com/ansible-collections/community.sops/issues/145, https://github.com/ansible-collections/community.sops/pull/146).

v1.6.1
======

Release Summary
---------------

Maintenance release.

Bugfixes
--------

- action plugin helper - fix handling of deprecations for ansible-core 2.14.2 (https://github.com/ansible-collections/community.sops/pull/136).
- various plugins - remove unnecessary imports (https://github.com/ansible-collections/community.sops/pull/133).

v1.6.0
======

Release Summary
---------------

Feature release improving the installation role.

Minor Changes
-------------

- install role - add ``sops_github_latest_detection`` option that allows to configure which method to use for detecting the latest release on GitHub. By default (``auto``) first tries to retrieve a list of recent releases using the API, and if that fails due to rate limiting, tries to obtain the latest GitHub release from a semi-documented URL (https://github.com/ansible-collections/community.sops/pull/133).
- install role - add ``sops_github_token`` option to allow passing a GitHub token. This can for example be used to avoid rate limits when using the role in GitHub Actions (https://github.com/ansible-collections/community.sops/pull/132).
- install role - implement another method to determine the latest release on GitHub than using the GitHub API, which can make installation fail due to rate-limiting (https://github.com/ansible-collections/community.sops/pull/131).

v1.5.0
======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- Automatically install GNU Privacy Guard (GPG) in execution environments. To install Mozilla sops a manual step needs to be added to the EE definition, see the collection's documentation for details (https://github.com/ansible-collections/community.sops/pull/98).

New Playbooks
-------------

- community.sops.install - Installs sops and GNU Privacy Guard on all remote hosts
- community.sops.install_localhost - Installs sops and GNU Privacy Guard on localhost

New Roles
---------

- community.sops.install - Install Mozilla sops

v1.4.1
======

Release Summary
---------------

Maintenance release to improve compatibility with future ansible-core releases.

Bugfixes
--------

- load_vars - ensure compatibility with newer versions of ansible-core (https://github.com/ansible-collections/community.sops/pull/121).

v1.4.0
======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- Allow to specify age keys as ``age_key``, or age keyfiles as ``age_keyfile`` (https://github.com/ansible-collections/community.sops/issues/116, https://github.com/ansible-collections/community.sops/pull/117).
- sops_encrypt - allow to specify age recipients (https://github.com/ansible-collections/community.sops/issues/116, https://github.com/ansible-collections/community.sops/pull/117).

v1.3.0
======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- All software licenses are now in the ``LICENSES/`` directory of the collection root, and the collection repository conforms to the `REUSE specification <https://reuse.software/spec/>`__ except for the changelog fragments (https://github.com/ansible-collections/community.crypto/sops/108, https://github.com/ansible-collections/community.sops/pull/113).
- sops vars plugin - added a configuration option to temporarily disable the vars plugin (https://github.com/ansible-collections/community.sops/pull/114).

v1.2.3
======

Release Summary
---------------

Fix formatting bug in documentation. No code changes.

v1.2.2
======

Release Summary
---------------

Maintenance release.

Bugfixes
--------

- Include ``simplified_bsd.txt`` license file for the ``sops`` module utils.

v1.2.1
======

Release Summary
---------------

Maintenance release with updated documentation.

v1.2.0
======

Release Summary
---------------

Collection release for inclusion in Ansible 4.9.0 and 5.1.0.

This release contains a change allowing to configure generic plugin options with ansible.cfg keys and env variables.

Minor Changes
-------------

- sops lookup and vars plugin - allow to configure almost all generic options by ansible.cfg entries and environment variables (https://github.com/ansible-collections/community.sops/pull/81).

Bugfixes
--------

- Fix error handling in calls of the ``sops`` binary when negative errors are returned (https://github.com/ansible-collections/community.sops/issues/82, https://github.com/ansible-collections/community.sops/pull/83).

v1.1.0
======

Release Summary
---------------

A minor release for inclusion in Ansible 4.2.0.

Minor Changes
-------------

- Avoid internal ansible-core module_utils in favor of equivalent public API available since at least Ansible 2.9 (https://github.com/ansible-collections/community.sops/pull/73).

New Plugins
-----------

Filter
~~~~~~

- community.sops.decrypt - Decrypt sops-encrypted data

v1.0.6
======

Release Summary
---------------

This release makes the collection compatible to the latest beta release of ansible-core 2.11.

Bugfixes
--------

- action_module plugin helper - make compatible with latest changes in ansible-core 2.11.0b3 (https://github.com/ansible-collections/community.sops/pull/58).
- community.sops.load_vars - make compatible with latest changes in ansible-core 2.11.0b3 (https://github.com/ansible-collections/community.sops/pull/58).

v1.0.5
======

Release Summary
---------------

This release fixes a bug that prevented correct YAML file to be created when the output was ending in `.yaml`.

Bugfixes
--------

- community.sops.sops_encrypt - use output type ``yaml`` when path ends with ``.yaml`` (https://github.com/ansible-collections/community.sops/pull/56).

v1.0.4
======

Release Summary
---------------

This is a security release, fixing a potential information leak in the ``community.sops.sops_encrypt`` module.

Security Fixes
--------------

- community.sops.sops_encrypt - mark the ``aws_secret_access_key`` and ``aws_session_token`` parameters as ``no_log`` to avoid leakage of secrets (https://github.com/ansible-collections/community.sops/pull/54).

v1.0.3
======

Release Summary
---------------

This release include some fixes to Ansible docs and required changes for inclusion in Ansible.

Bugfixes
--------

- community.sops.sops lookup plugins - fix wrong format of Ansible variables so that these are actually used (https://github.com/ansible-collections/community.sops/pull/51).
- community.sops.sops vars plugins - remove non-working Ansible variables (https://github.com/ansible-collections/community.sops/pull/51).

v1.0.2
======

Release Summary
---------------

Fix of 1.0.1 release which had no changelog entry.

v1.0.1
======

Release Summary
---------------

Re-release of 1.0.0 to counteract error during release.

v1.0.0
======

Release Summary
---------------

First stable release. This release is expected to be included in Ansible 3.0.0.

Minor Changes
-------------

- All plugins and modules: allow to pass generic sops options with new options ``config_path``, ``enable_local_keyservice``, ``keyservice``. Also allow to pass AWS parameters with options ``aws_profile``, ``aws_access_key_id``, ``aws_secret_access_key``, and ``aws_session_token`` (https://github.com/ansible-collections/community.sops/pull/47).
- community.sops.sops_encrypt - allow to pass encryption-specific options ``kms``, ``gcp_kms``, ``azure_kv``, ``hc_vault_transit``, ``pgp``, ``unencrypted_suffix``, ``encrypted_suffix``, ``unencrypted_regex``, ``encrypted_regex``, ``encryption_context``, and ``shamir_secret_sharing_threshold`` to sops (https://github.com/ansible-collections/community.sops/pull/47).

v0.2.0
======

Release Summary
---------------

This release adds features for the lookup and vars plugins.

Minor Changes
-------------

- community.sops.sops lookup plugin - add ``empty_on_not_exist`` option which allows to return an empty string instead of an error when the file does not exist (https://github.com/ansible-collections/community.sops/pull/33).
- community.sops.sops vars plugin - add option to control caching (https://github.com/ansible-collections/community.sops/pull/32).
- community.sops.sops vars plugin - add option to determine when vars are loaded (https://github.com/ansible-collections/community.sops/pull/32).

v0.1.0
======

Release Summary
---------------

First release of the `community.sops` collection!
This release includes multiple plugins: an `action` plugin, a `lookup` plugin and a `vars` plugin.

New Plugins
-----------

Lookup
~~~~~~

- community.sops.sops - Read sops encrypted file contents

Vars
~~~~

- community.sops.sops - Loading sops-encrypted vars files

New Modules
-----------

- community.sops.load_vars - Load sops-encrypted variables from files, dynamically within a task
- community.sops.sops_encrypt - Encrypt data with sops

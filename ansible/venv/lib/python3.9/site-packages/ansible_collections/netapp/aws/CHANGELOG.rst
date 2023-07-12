=======================================
NetApp AWS CVS Collection Release Notes
=======================================

.. contents:: Topics


v21.7.0
=======

Minor Changes
-------------

- PR1 - allow usage of Ansible module group defaults - for Ansible 2.12+.

v21.6.0
=======

Minor Changes
-------------

- all modules - ability to trace API calls and responses.

Bugfixes
--------

- all modules - fix traceback TypeError 'NoneType' object is not subscriptable when URL points to a web server.

v21.2.0
=======

Bugfixes
--------

- all modules - disable logging for ``api_key`` and ``secret_key`` values.
- all modules - prevent infinite loop when asynchronous action fails.
- all modules - report error if response does not contain valid JSON.
- aws_netapp_cvs_filesystems - fix KeyError when exportPolicy is not present.

v20.9.0
=======

Minor Changes
-------------

- Fix pylint or flake8 warnings reported by galaxy importer.

v20.8.0
=======

Minor Changes
-------------

- add "elements:" and update "required:" to match module requirements.
- use a three group format for version_added. So 2.7 becomes 2.7.0. Same thing for 2.8 and 2.9.

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

v19.10.0
========

Minor Changes
-------------

- refactor existing modules as a collection

v2.9.0
======

New Modules
-----------

- netapp.aws.aws_netapp_cvs_active_directory - NetApp AWS CloudVolumes Service Manage Active Directory.
- netapp.aws.aws_netapp_cvs_filesystems - NetApp AWS Cloud Volumes Service Manage FileSystem.
- netapp.aws.aws_netapp_cvs_pool - NetApp AWS Cloud Volumes Service Manage Pools.
- netapp.aws.aws_netapp_cvs_snapshots - NetApp AWS Cloud Volumes Service Manage Snapshots.

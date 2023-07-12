==========================
Google.Cloud Release Notes
==========================

.. contents:: Topics


v1.1.3
======

Bugfixes
--------

- gcp_compute_instance_info: fix incorrect documentation for filter which incorrectly pointed to the gcloud filter logic rather than the API (fixes #549)

v1.1.2
======

Bugfixes
--------

- fix `gcp_compute` no longer being a valid name of the inventory plugin

v1.1.1
======

Bugfixes
--------

- fix collection to work with Python 2.7

v1.1.0
======

Minor Changes
-------------

- GCE inventory plugin - a new option ``name_suffix``, to add a suffix to the name parameter.

Bugfixes
--------

- Disk has been fixed to send the sourceSnapshot parameter.
- gcp_cloudtasks_queue - was not functional before, and is now functional.
- gcp_compute_* - these resources use the correct selflink (www.googleapis.com) as the domain, no longer erroneously reporting changes after an execution.
- gcp_compute_backend_service - no longer erroneously reports changes after an execution for ``capacity_scaler``.
- gcp_container_cluster - support GKE clusters greater than 1.19+, which cannot use basic-auth.
- gcp_crypto_key - skip_initial_version_creation defaults to the correct value.
- gcp_iam_role - now properly undeletes and recognizes soft deleted roles as absent.
- gcp_iam_role - update of a role is functional (GitHub
- gcp_spanner_database - recognize a non-existent resource as absent.
- gcp_storage_object - fix for correct version of dependency requirement.

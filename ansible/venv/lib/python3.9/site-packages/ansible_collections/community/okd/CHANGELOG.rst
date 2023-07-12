============================
OKD Collection Release Notes
============================

.. contents:: Topics


v2.3.0
======

Bugfixes
--------

- openshift_adm_groups_sync - initialize OpenshiftGroupSync attributes early to avoid Attribute error (https://github.com/openshift/community.okd/issues/155).
- openshift_auth - Review the way the discard process is working, add openshift algorithm to convert token to resource object name (https://github.com/openshift/community.okd/issues/176).

New Modules
-----------

- openshift_adm_prune_builds - Prune old completed and failed builds
- openshift_build - Start a new build or Cancel running, pending, or new builds.

v2.2.0
======

Minor Changes
-------------

- add action groups to runtime.yml (https://github.com/openshift/community.okd/issues/41).

Bugfixes
--------

- fix ocp auth failing against cluster api url with trailing slash (https://github.com/openshift/community.okd/issues/139)

New Modules
-----------

- openshift_adm_migrate_template_instances - Update TemplateInstances to point to the latest group-version-kinds
- openshift_adm_prune_auth - Removes references to the specified roles, clusterroles, users, and groups
- openshift_adm_prune_deployments - Remove old completed and failed deployment configs
- openshift_adm_prune_images - Remove unreferenced images
- openshift_import_image - Import the latest image information from a tag in a container image registry.
- openshift_registry_info - Display information about the integrated registry.

v2.1.0
======

Minor Changes
-------------

- add support for turbo mode (https://github.com/openshift/community.okd/pull/102).
- openshift_route - Add support for Route annotations (https://github.com/ansible-collections/community.okd/pull/99).

Bugfixes
--------

- fix broken links in Automation Hub for redhat.openshift (https://github.com/openshift/community.okd/issues/100).

v2.0.1
======

Minor Changes
-------------

- increase kubernetes.core dependency version (https://github.com/openshift/community.okd/pull/97).

v2.0.0
======

Major Changes
-------------

- update to use kubernetes.core 2.0 (https://github.com/openshift/community.okd/pull/93).

Minor Changes
-------------

- Added documentation for the ``community.okd`` collection.
- openshift - inventory plugin supports FQCN ``redhat.openshift``.

Breaking Changes / Porting Guide
--------------------------------

- drop python 2 support (https://github.com/openshift/community.okd/pull/93).

Bugfixes
--------

- fixes test suite to use correct versions of python and dependencies (https://github.com/ansible-collections/community.okd/pull/89).
- openshift_process - fix module execution when template does not include a message (https://github.com/ansible-collections/community.okd/pull/87).

v1.1.2
======

Bugfixes
--------

- include requirements.txt in downstream build process (https://github.com/ansible-collections/community.okd/pull/81).

v1.1.1
======

Bugfixes
--------

- add missing requirements.txt file needed for execution environments (https://github.com/ansible-collections/community.okd/pull/78).
- openshift_route - default to ``no_log=False`` for the ``key`` parameter in TLS configuration to fix sanity failures (https://github.com/ansible-collections/community.okd/pull/77).
- restrict molecule version to <3.3.0 to address breaking change (https://github.com/ansible-collections/community.okd/pull/77).
- update CI to work with ansible 2.11 (https://github.com/ansible-collections/community.okd/pull/80).

v1.1.0
======

Minor Changes
-------------

- increase the kubernetes.core dependency version number (https://github.com/ansible-collections/community.okd/pull/71).

v1.0.2
======

Minor Changes
-------------

- restrict the version of kubernetes.core dependency (https://github.com/ansible-collections/community.okd/pull/66).

v1.0.1
======

Bugfixes
--------

- Generate downstream redhat.openshift documentation (https://github.com/ansible-collections/community.okd/pull/59).

v1.0.0
======

Minor Changes
-------------

- Released version 1 to Automation Hub as redhat.openshift (https://github.com/ansible-collections/community.okd/issues/51).

v0.3.0
======

Major Changes
-------------

- Add openshift_process module for template rendering and optional application of rendered resources (https://github.com/ansible-collections/community.okd/pull/44).
- Add openshift_route module for creating routes from services (https://github.com/ansible-collections/community.okd/pull/40).

New Modules
-----------

- openshift_process - Process an OpenShift template.openshift.io/v1 Template
- openshift_route - Expose a Service as an OpenShift Route.

v0.2.0
======

Major Changes
-------------

- openshift_auth - new module (migrated from k8s_auth in community.kubernetes) (https://github.com/ansible-collections/community.okd/pull/33).

Minor Changes
-------------

- Add a contribution guide (https://github.com/ansible-collections/community.okd/pull/37).
- Use the API Group APIVersion for the `Route` object (https://github.com/ansible-collections/community.okd/pull/27).

New Modules
-----------

- openshift_auth - Authenticate to OpenShift clusters which require an explicit login step

v0.1.0
======

Major Changes
-------------

- Add custom k8s module, integrate better Molecule tests (https://github.com/ansible-collections/community.okd/pull/7).
- Add downstream build scripts to build redhat.openshift (https://github.com/ansible-collections/community.okd/pull/20).
- Add openshift connection plugin, update inventory plugin to use it (https://github.com/ansible-collections/community.okd/pull/18).
- Initial content migration from community.kubernetes (https://github.com/ansible-collections/community.okd/pull/3).

Minor Changes
-------------

- Add incluster Makefile target for CI (https://github.com/ansible-collections/community.okd/pull/13).
- Add tests for inventory plugin (https://github.com/ansible-collections/community.okd/pull/16).
- CI Documentation for working with Prow (https://github.com/ansible-collections/community.okd/pull/15).
- Docker container can run as an arbitrary user (https://github.com/ansible-collections/community.okd/pull/12).
- Dockerfile now is properly set up to run tests in a rootless container (https://github.com/ansible-collections/community.okd/pull/11).
- Integrate stale bot for issue queue maintenance (https://github.com/ansible-collections/community.okd/pull/14).

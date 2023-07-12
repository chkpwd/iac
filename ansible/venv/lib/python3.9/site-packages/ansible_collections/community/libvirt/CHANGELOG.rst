===============================
Community.Libvirt Release Notes
===============================

.. contents:: Topics


v1.2.0
======

Release Summary
---------------

This is the minor release of the ``community.libvirt`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Minor Changes
-------------

- libvirt - add extra guest information to inventory (https://github.com/ansible-collections/community.libvirt/pull/113).
- libvirt - replace the calls to listDomainsID() and listDefinedDomains() with listAllDomains() in find_vm() (https://github.com/ansible-collections/community.libvirt/pull/117)

Bugfixes
--------

- virt_net - fix modify function which was not idempotent, depending on whether the network was active. See https://github.com/ansible-collections/community.libvirt/issues/107.
- virt_pool - crashed out if pool didn't contain a target path. Fix allows this not to be set. (https://github.com/ansible-collections/community.libvirt/issues/129).

v1.1.0
======

Release Summary
---------------

This is the minor release of the ``community.libvirt`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release 1.0.2.

Bugfixes
--------

- replace deprecated ``distutils.spawn.find_executable`` with Ansible's ``get_bin_path`` in ``_search_executable`` function.

v1.0.2
======

Release Summary
---------------

This is the patch release of the ``community.libvirt`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after release 1.0.1.

Bugfixes
--------

- libvirt inventory plugin - Use FQCN for the inventory plugin name for compatibility with Ansible 2.10 and above (https://github.com/ansible-collections/community.libvirt/pull/73).

v1.0.1
======

Bugfixes
--------

- libvirt_qemu - Mitigate a CPU hammering active wait loop
- libvirt_qemu - add import error handling
- virt - Correctly get the error message from libvirt
- virt - Return "changed" status when using "define" command and domain XML was updated
- virt - The define action searchs for the domain name into the xml definition to determine if the domain needs to be created or updated. The xml variable contains the parsed definition but doesn't guarantee the existence of the name tag. This change targets to fix the scenario where the xml var is not empty but doesn't contain a name tag.
- virt_net - The name parameter is not required for the list_nets or facts command so we adjust the module to allow for that.

v1.0.0
======

Major Changes
-------------

- added generic libvirt inventory plugin
- removed libvirt_lxc inventory script

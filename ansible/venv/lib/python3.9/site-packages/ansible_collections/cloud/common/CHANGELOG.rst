==========================
cloud.common Release Notes
==========================

.. contents:: Topics


v2.1.3
======

Minor Changes
-------------

- sanity - fix sanity errors (https://github.com/ansible-collections/cloud.common/issues/106)
- units - ensure tests/units follow the Ansible-defined unit tests structure (https://github.com/ansible-collections/cloud.common/issues/89)

Bugfixes
--------

- module_utils/turbo/server - import needed library into the right place (https://github.com/ansible-collections/cloud.common/pull/120)

v2.1.2
======

Bugfixes
--------

- Ensure we don't shutdown the server when we've still got some ongoing tasks (https://github.com/ansible-collections/cloud.common/pull/109).

v2.1.1
======

Minor Changes
-------------

- Move the content of README_ansible_turbo.module.rst in the main README.md to get visibility on Ansible Galaxy.

Bugfixes
--------

- fix parameters with aliases not being passed through (https://github.com/ansible-collections/cloud.common/issues/91).
- fix turbo mode loading incorrect module (https://github.com/ansible-collections/cloud.common/pull/102).
- turbo - Ensure we don't call the module with duplicated aliased parameters.

v2.1.0
======

Minor Changes
-------------

- Cosmetic changes in the documentation for the inclusion in the Ansible collection.
- turbo - Extend the unit-test coverage.
- turbo - Use a BSD license for the module_utils and plugin_utils files.
- turbo - add support for coroutine for lookup plugins (https://github.com/ansible-collections/cloud.common/pull/75).

v2.0.4
======

Major Changes
-------------

- turbo - enable turbo mode for lookup plugins

Bugfixes
--------

- add exception handler to main async loop (https://github.com/ansible-collections/cloud.common/pull/67).
- pass current task's environment through to execution (https://github.com/ansible-collections/cloud.common/pull/69).
- turbo - AnsibleTurboModule was missing some _ansible_facts variable like _diff, _ansible_tmpdir. (https://github.com/ansible-collections/cloud.common/issues/65)
- turbo - honor the ``remote_tmp`` configuration key.

v2.0.3
======

Bugfixes
--------

- Introduces a fix for the future Python 3.10 (#53)
- turbo - make sure socket doesn't close prematurely, preventing issues with large amounts of data passed as module parameters (https://github.com/ansible-collections/cloud.common/issues/61)

v2.0.2
======

Bugfixes
--------

- Introduces a fix for the future Python 3.10 (#53)
- fail_json method should honor kwargs now when running embedded in server.

v2.0.1
======

Bugfixes
--------

- The profiler is now properly initialized.
- Use the argument_spec values to determine which option should actually be used.
- fix exception messages containing extra single quotes (https://github.com/ansible-collections/cloud.common/pull/46).

v2.0.0
======

Minor Changes
-------------

- The ``EmbeddedModuleFailure`` and ``EmbeddedModuleUnexpectedFailure`` exceptions now handle the ``__repr__`` and ``__str__`` method. This means Python is able to print a meaningful output.
- The modules must now set the ``collection_name`` of the ``AnsibleTurboModule`` class. The content of this attribute is used to build the path of the UNIX socket.
- When the background service is started in a console without the ``--daemon`` flag, it now prints information what it runs.
- ``argument_spec`` is now evaluated server-side.
- fail_json now accept and collect extra named arguments.
- raise an exception if the output of module execution cannot be parsed.
- the ``turbo_demo`` module now return the value of counter.
- the user get an error now an error if a module don't raise ``exit_json()`` or ``fail_json()``.

Bugfixes
--------

- the debug mode now work as expected. The ``_ansible_*`` variables are properly passed to the module.

v1.1.0
======

Minor Changes
-------------

- ansible_module.turbo - the cache is now associated with the collection, if two collections use a cache, two background services will be started.

Bugfixes
--------

- Ensure the background service starts properly on MacOS (https://github.com/ansible-collections/cloud.common/pull/16)
- do not silently skip parameters when the value is ``False``

v1.0.2
======

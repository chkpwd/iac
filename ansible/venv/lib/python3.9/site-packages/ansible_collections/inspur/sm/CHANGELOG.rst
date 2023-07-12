=======================
Inspur.sm Release Notes
=======================

.. contents:: Topics


v2.3.0
======

Minor Changes
-------------

- Modify the tags fields in Galaxy.yml.
- edit_power_budget add 'domain' field.
- edit_snmp module add 'v1status','v2status','v3status','read_community','read_write_community' fields.
- edit_snmp_trap module modifies the version value.
- eidt_ad module add 'ssl_enalbe' field, modify the timeout field description.
- eidt_ldisk module add 'duration' field.
- eidt_pdisk module add 'duration' field.
- modify the edit_log_setting module description.
- modify the edit_ncsi module description and parameter values.
- user module add 'uid','access' fields.
- user_group module add 'general','power','media','kvm','security','debug','self' fields.

Bugfixes
--------

- edit_snmp_trap module modifies input parameter errors in the example.

v2.2.0
======

Minor Changes
-------------

- Edit_dns adds new field to M6 model.
- Modify ansible-test to add asnible 2.13,2.14 version.
- Modify the authors and tags fields in Galaxy.yml.
- Update the document.

v2.0.0
======

Minor Changes
-------------

- Add the onboard_disk_info module.
- Modified logical disk Settings, added logical disk Settings for M6 PMC card.
- Modify the edit_pdisk function to add new parameters.
- The user module adds the mailbox field.

New Modules
-----------

- inspur.sm.onboard_disk_info - Get onboard disks information.

v1.2.0
======

Minor Changes
-------------

- Compatible with M6 models, add M6 specific fields.

Deprecated Features
-------------------

- add_ad_group - This feature will be removed in inspur.sm.add_ad_group 3.0.0. replaced with inspur.sm.ad_group.
- add_ldap_group - This feature will be removed in inspur.sm.add_ldap_group 3.0.0. replaced with inspur.sm.ldap_group.
- add_user - This feature will be removed in inspur.sm.add_user 3.0.0. replaced with inspur.sm.user.
- add_user_group - This feature will be removed in inspur.sm.add_user_group 3.0.0. replaced with inspur.sm.user_group.
- del_ad_group - This feature will be removed in inspur.sm.del_ad_group 3.0.0. replaced with inspur.sm.ad_group.
- del_ldap_group - This feature will be removed in inspur.sm.del_ldap_group 3.0.0. replaced with inspur.sm.ldap_group.
- del_user - This feature will be removed in inspur.sm.del_user 3.0.0. replaced with inspur.sm.user.
- del_user_group - This feature will be removed in inspur.sm.del_user_group 3.0.0. replaced with inspur.sm.user_group.
- edit_ad_group - This feature will be removed in inspur.sm.edit_ad_group 3.0.0. replaced with inspur.sm.ad_group.
- edit_ldap_group - This feature will be removed in inspur.sm.edit_ldap_group 3.0.0. replaced with inspur.sm.ldap_group.
- edit_user - This feature will be removed in inspur.sm.edit_user 3.0.0. replaced with inspur.sm.user.
- edit_user_group - This feature will be removed in inspur.sm.edit_user_group 3.0.0. replaced with inspur.sm.user_group.

v1.1.3
======

Bugfixes
--------

- Add ansible 2.11 test.
- Add the no_log=true attribute to some modules.

v1.1.2
======

Bugfixes
--------

- Update 'supports_check_mode=False' to 'supports_check_mode=True' for all modules ending in '_info'.

v1.1.1
======

Minor Changes
-------------

- Modified version information to 1.1.1 in galaxy.yml.

Bugfixes
--------

- Update version_added field in ad_group, ldap_group, user, and user_group modules to match the collection version they were first introduced in.

v1.1.0
======

Minor Changes
-------------

- Add CODE_OF_CONDUCT.md file.
- Add a meta/runtime.yml file.
- Add the code of conduct to the README.md file.
- Delete the Collections imported in the adapter_info.py.
- Delete the Collections imported in the module.
- Documentation, examples, and return use FQCNs to M(..).
- Modify ansible_test.yml to add push trigger rule.
- Modify ansibled-test. yml file, add timing execution script, run environment only keep Python 3.8 version.
- Modify inspur_sm_sdk in README.md to inspursmsdk.
- Modify paybooks,Using FQCN.
- Modify the README.md file to add Ansible Code of Conduct (COC).
- Modify the README.md file to add content for releasing, versioning and deprecation(https://github.com/ISIB-Group/inspur.sm/issues/27).
- Modify the README.md file to change the supported Anible version to 2.10.0
- Modify the ansible-test.yml file to Remove the Python Version from the Run sanity tests.
- Modify the ansible-test.yml file to add Ansible and Python versions.
- Modify the description of Ansible in README.md.
- Modify the format of DOCUMENTATION on Required in the module.
- Modify the github repository path referenced in galaxy.yml.
- Modify the module_utils/ism.py file to add check mode processing.
- Modify the state of chenged in the module when the operation changes.
- Modify the value of supports_check_mode in the module to False.
- Regenerate the.rst file.

v1.0.3
======

Release Summary
---------------

Modify the content format of 'readme.md'.

v1.0.2
======

Release Summary
---------------

Modify the generated.RST file style.

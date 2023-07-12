===================================
Infoblox.Nios_Modules Release Notes
===================================

.. contents:: Topics

v1.5.0
======

Release Summary
---------------
- Added new module - NIOS Range with Create, Update and Delete features
- Added new feature - Member Assignment to Networks with add and remove functionality
- Fixes Unable to Update/Delete EAs using Ansible plugin
- Fixes Static Allocation of IPV4 address of A Record
- Updates default WAPI version to 2.9
- Added Grid Master Candidate feature

Major Changes
-------------
- Added NIOS Range module with Create, Update and Delete features `#152 <https://github.com/infobloxopen/infoblox-ansible/pull/152>`_
- Added Member Assignment to network and ranges `#152 <https://github.com/infobloxopen/infoblox-ansible/pull/152>`_
- Added Grid Master Candidate feature `#152 <https://github.com/infobloxopen/infoblox-ansible/pull/152>`_
- Fixes issue unable to update/delete EAs using Ansible plugin `#180 <https://github.com/infobloxopen/infoblox-ansible/pull/180>`_
- Fixes static and dynamic allocation of IPV4 address of A Record `#182 <https://github.com/infobloxopen/infoblox-ansible/pull/182>`_
- Fixes to Update host name of  NIOS member `#176 <https://github.com/infobloxopen/infoblox-ansible/pull/176>`_
- Updates default WAPI version to 2.9 `#176 <https://github.com/infobloxopen/infoblox-ansible/pull/176>`_

Bugfixes
---------
- Fixes Update A Record having multiple records with same name and different IP `#182 <https://github.com/infobloxopen/infoblox-ansible/pull/182>`_


v1.4.1
======

Release Summary
---------------
- Ansible Lookup modules can specify network_view to which a network/ip belongs
- Fixes camelCase issue while updating 'nios_network_view' with 'new_name'
- Fixes issue to allocate ip to a_record dynamically
- Updates 'nios_a_record' name with multiple ips having same name

Minor Changes
-------------
- Fix to specify network_view in lookup modules to return absolute network/ip `#157 <https://github.com/infobloxopen/infoblox-ansible/pull/157>`_
- Fix to camelcase issue for updating 'nios_network_view' name `#163 <https://github.com/infobloxopen/infoblox-ansible/pull/163>`_
- Fix to allocate ip to a_record dynamically `#163 <https://github.com/infobloxopen/infoblox-ansible/pull/163>`_
- Fix to update 'nios_a_record' name with multiple ips having same name `#164 <https://github.com/infobloxopen/infoblox-ansible/pull/164>`_
- Fix to changelog yaml file with linting issues `#161 <https://github.com/infobloxopen/infoblox-ansible/pull/161>`_


v1.4.0
======

Release Summary
---------------
- For ansible module, added certificate authentication feature
- Few bug fixes in ansible module nios network

Major Changes
-------------
- Feature for extra layer security, with `cert` and `key` parameters in playbooks for authenticating using certificate and key .pem file absolute path `#154 <https://github.com/infobloxopen/infoblox-ansible/pull/154>`
- Fix to remove issue causing due to template attr in deleting network using Ansible module nios network `#147 <https://github.com/infobloxopen/infoblox-ansible/pull/147>`_


v1.3.0
======

Release Summary
---------------
- Issue fixes to create TXT record with equals sign
- For nonexistent record, update operation creates the new record
- For nonexistent IPv4Address, update operation creates a new A record with new_ipv4addr

Major Changes
-------------
- Update operation using `old_name` and `new_name` for the object with dummy name in `old_name` (which does not exist in system) will not create a new object in the system. An error will be thrown stating the object does not exist in the system `#129 <https://github.com/infobloxopen/infoblox-ansible/pull/129>`_
- Update `text` field of TXT Record `#128 <https://github.com/infobloxopen/infoblox-ansible/pull/128>`_

Bugfixes
---------
- Fix to create TXT record with equals sign `#128 <https://github.com/infobloxopen/infoblox-ansible/pull/128>`_

  
v1.2.2
======

Release Summary
---------------
- Issue fixes to create PTR record in different network views
- Support extended to determine whether the DTC server is disabled or not

Minor Changes
-------------
- Fix to create PTR record in different network views `#103 <https://github.com/infobloxopen/infoblox-ansible/pull/103>`_
- Remove use_option for DHCP option 60 `#104 <https://github.com/infobloxopen/infoblox-ansible/pull/104>`_
- Allow specifying a template when creating a network `#105 <https://github.com/infobloxopen/infoblox-ansible/pull/105>`_
- Fix unit and sanity test issues `#117 <https://github.com/infobloxopen/infoblox-ansible/pull/117>`_
- Expanding for disable value `#119 <https://github.com/infobloxopen/infoblox-ansible/pull/119>`_


v1.2.1
======

Release Summary
---------------
Added tags to support release on Ansible Automation Hub

Minor Changes
-------------
Added tags 'cloud' and 'networking' in 'galaxy.yaml'


v1.2.0
======
Release Summary
---------------
- Issue fixes to update A Record using 'next_available_ip' function
- Added a new feature - Update canonical name of the CNAME Record
- Updated the 'required' fields in modules

Minor Changes
-------------
- Updated 'required' field in modules `#99 <https://github.com/infobloxopen/infoblox-ansible/pull/99>`_
- Following options are made required in the modules

.. list-table:: 
   :widths: 25 25
   :header-rows: 1

   * - Record
     - Option made required
   * - A
     - ipv4addr
   * - AAAA
     - ipv6addr
   * - CNAME
     - canonical     
   * - MX
     - mail_exchanger, preference     
   * - PTR
     - ptrdname
     
Bugfixes
-------------
- nios_a_record module - KeyError: 'old_ipv4addr' `#79 <https://github.com/infobloxopen/infoblox-ansible/issues/79>`_
- Ansible playbook fails to update canonical name of CName Record `#97 <https://github.com/infobloxopen/infoblox-ansible/pull/97>`_


v1.1.2
======
Release Summary
---------------
- Issue fixes and standardization of inventory plugin and lookup modules as per Ansible guidelines
- Directory restructure and added integration & unit tests

Minor Changes
-------------
- Changes in inventory and lookup plugins documentation `#85 <https://github.com/infobloxopen/infoblox-ansible/pull/85>`_
- Directory restructure and added integration & unit tests `#87 <https://github.com/infobloxopen/infoblox-ansible/pull/87>`_

Bugfixes
-------------
- Handle NoneType parsing in nios_inventory.py `#81 <https://github.com/infobloxopen/infoblox-ansible/pull/81>`_
- Check all dhcp options, not just first one `#83 <https://github.com/infobloxopen/infoblox-ansible/pull/83>`_


v1.1.1
======
Release Summary
---------------
- Support for creating IPv6 Fixed Address with DUID
- Support added to return the next available IP address for an IPv6 network
- Modules made compatible to work with ansible-core 2.11
- Issue fixes and standardization of modules as per Ansible guidelines

Minor Changes
-------------
- The modules are standardized as per Ansible guidelines

Bugfixes
-------------
- Implemented the bugfixes provided by Ansible `community.general`
- Update the name of existing A and AAAA records `#70 <https://github.com/infobloxopen/infoblox-ansible/pull/70>`_
- Update of comment field of SRV, PTR and NAPTR records failing with the following error: 
  ```[Err: fatal: [localhost]: FAILED! => {"changed": false, "code": "Client.Ibap.Proto", "msg": "Field is not allowed for update: view", "operation": "update_object", "type": "AdmConProtoError"}]``` 
  `#70 <https://github.com/infobloxopen/infoblox-ansible/pull/70>`_
- PTR Record failed to update and raises KeyError for view field `#70 <https://github.com/infobloxopen/infoblox-ansible/pull/70>`_
- Update comment field and delete an existing Fixed Address `#73 <https://github.com/infobloxopen/infoblox-ansible/pull/73>`_
- GitHub issue fix - Lookup module for next available IPV6 `#31 <https://github.com/infobloxopen/infoblox-ansible/issues/31>`_
- GitHub issue fix - [nios_zone] changing a nios_zone does not work `#60 <https://github.com/infobloxopen/infoblox-ansible/issues/60>`_
- GitHub issue fix - Getting an error, running every module `#67 <https://github.com/infobloxopen/infoblox-ansible/issues/67>`_
- GitHub issue fix - Error - Dictionary Issues `#68 <https://github.com/infobloxopen/infoblox-ansible/issues/68>`_
- GitHub issue fix - Examples for lookups don't work as written `#72 <https://github.com/infobloxopen/infoblox-ansible/issues/72>`_
- Sanity fixes as per Ansible guidelines to all modules


v1.1.0
======

Release Summary
---------------

This release provides plugins for NIOS DTC

New Modules
-----------

- infoblox.nios_modules.nios_dtc_lbdn - Configure Infoblox NIOS DTC LBDN
- infoblox.nios_modules.nios_dtc_pool - Configure Infoblox NIOS DTC Pool
- infoblox.nios_modules.nios_dtc_server - Configure Infoblox NIOS DTC Server
- infoblox.nios_modules.nios_restartservices - Restart grid services.

v1.0.2
======

Release Summary
---------------

This release provides compatibilty for Ansible v3.0.0

Minor Changes
-------------

- Fixed the ignored sanity errors required for Ansible 3.0.0 collection
- Made it compatible for Ansible v3.0.0

v1.0.1
======

Release Summary
---------------

This release provides compatibilty for Ansible v3.0.0

Minor Changes
-------------

- Made it compatible for Ansible v3.0.0

v1.0.0
======

Release Summary
---------------

First release of the `nios_modules` collection! This release includes multiple plugins:- an `api` plugin, a `network` plugin, a `nios` plugin, a `nios_inventory` plugin, a `lookup plugin`, a `nios_next_ip` plugin, a `nios_next_network` plugin 

New Plugins
-----------

Lookup
~~~~~~

- infoblox.nios_modules.nios - Query Infoblox NIOS objects
- infoblox.nios_modules.nios_next_ip - Return the next available IP address for a network
- infoblox.nios_modules.nios_next_network - Return the next available network range for a network-container

New Modules
-----------

- infoblox.nios_modules.nios_a_record - Configure Infoblox NIOS A records
- infoblox.nios_modules.nios_aaaa_record - Configure Infoblox NIOS AAAA records
- infoblox.nios_modules.nios_cname_record - Configure Infoblox NIOS CNAME records
- infoblox.nios_modules.nios_dns_view - Configure Infoblox NIOS DNS views
- infoblox.nios_modules.nios_fixed_address - Configure Infoblox NIOS DHCP Fixed Address
- infoblox.nios_modules.nios_host_record - Configure Infoblox NIOS host records
- infoblox.nios_modules.nios_member - Configure Infoblox NIOS members
- infoblox.nios_modules.nios_mx_record - Configure Infoblox NIOS MX records
- infoblox.nios_modules.nios_naptr_record - Configure Infoblox NIOS NAPTR records
- infoblox.nios_modules.nios_network - Configure Infoblox NIOS network object
- infoblox.nios_modules.nios_network_view - Configure Infoblox NIOS network views
- infoblox.nios_modules.nios_nsgroup - Configure Infoblox NIOS Nameserver Groups
- infoblox.nios_modules.nios_ptr_record - Configure Infoblox NIOS PTR records
- infoblox.nios_modules.nios_srv_record - Configure Infoblox NIOS SRV records
- infoblox.nios_modules.nios_txt_record - Configure Infoblox NIOS txt records
- infoblox.nios_modules.nios_zone - Configure Infoblox NIOS DNS zones

# Infoblox NIOS Modules for Ansible Collections

About 
======

Infoblox NIOS Modules for Ansible Collections allows managing your NIOS objects
through APIs.
It, thus, enables the DNS and IPAM automation of VM workloads that are
deployed across multiple platforms. The `nios_modules` collection
provides modules and plugins for managing the networks, IP addresses,
and DNS records in NIOS. This collection is hosted on Ansible Galaxy
under `infoblox.nios_modules`.

Modules Overview
=================

The `infoblox.nios_modules` collection has the following content:

Modules
--------

-   `nios_a_record` – Configure Infoblox NIOS A records

-   `nios_aaaa_record` – Configure Infoblox NIOS AAAA records

-   `nios_cname_record` – Configure Infoblox NIOS CNAME records

-   `nios_dns_view` – Configure Infoblox NIOS DNS views

-   `nios_dtc_lbdn` – Configure Infoblox NIOS DTC LBDN records

-   `nios_dtc_pool` – Configure Infoblox NIOS DTC pools

-   `nios_dtc_server` – Configure Infoblox NIOS DTC server records

-   `nios_fixed_address` – Configure Infoblox NIOS DHCP Fixed Address

-   `nios_host_record` – Configure Infoblox NIOS host records

-   `nios_member` – Configure Infoblox NIOS members

-   `nios_mx_record` – Configure Infoblox NIOS MX records

-   `nios_naptr_record` – Configure Infoblox NIOS NAPTR records

-   `nios_network` – Configure Infoblox NIOS network object

-   `nios_network_view` – Configure Infoblox NIOS network views

-   `nios_nsgroup` – Configure Infoblox DNS Nameserver Groups

-   `nios_ptr_record` – Configure Infoblox NIOS PTR records

-   `nios_range` - Configure Infoblox NIOS Network Range object

-   `nios_restartservices` - Controlled restart of Infoblox NIOS services

-   `nios_srv_record` – Configure Infoblox NIOS SRV records

-   `nios_txt_record` – Configure Infoblox NIOS txt records

-   `nios_zone` – Configure Infoblox NIOS DNS zones

Plugins
--------

-   `nios_inventory`: List all the hosts with records created in NIOS

-   `nios_lookup`: Look up queries for NIOS database objects

-   `nios_next_ip`: Returns the next available IP address for a network

-   `nios_next_network`: Returns the next available network addresses
    for a given network CIDR

Installation 
=============

Dependencies
------------

-   Python version 3.8 or later

-   Ansible version 2.12 or later

-   NIOS 8.5.x or later

Prerequisites
-------------

Install the infoblox-client WAPI package. To install, run the following command:

```shell
$ pip install infoblox-client
```

Installation of nios_modules Collection
----------------------------------------

The `nios_modules` collection can be installed either from Ansible Galaxy
or directly from git. It is recommended to install collections from
Ansible Galaxy as those are more stable than the ones in the git
branch.

### Installation from Ansible Galaxy
- To directly install the `nios_modules` collection from [Ansible Galaxy](https://galaxy.ansible.com/infoblox/nios_modules), run the following command:
    - ```
       $ ansible-galaxy collection install infoblox.nios_modules
      ```
    - The collection folder would be installed at
      ```
       ~/.ansible/collections/ansible_collections/infoblox/nios_modules
      ```
      
- For offline installation on the Ansible control machine, download the required tar archive version of the collection from [Infoblox Nios Modules collections](https://galaxy.ansible.com/infoblox/nios_modules) and run the command given below in `~/.ansible` directory:
    - ```
      $ ansible-galaxy collection install infoblox-nios_modules-<version>.tar.gz -p ./collections
      ```

### Installation from GitHub
- Install the collection directly from the [GitHub](https://github.com/infobloxopen/infoblox-ansible) repository using the latest commit on the master branch:
    - ```
      $ ansible-galaxy collection install git+https://github.com/infobloxopen/infoblox-ansible.git,master
      ```

- For offline installation on the Ansible control machine, to git clone and install from this repo, follow these steps:

    -   **Clone the repo:**

        ```
        $ git clone https://github.com/infobloxopen/infoblox-ansible.git
        ```

    -   **Build the collection:**

        To build a collection, run the following command from inside the
        root directory of the collection:
        ```
        $ ansible-galaxy collection build
        ```
        This creates a tarball of the built collection in the current directory.

    -   **Install the collection:**

        ```
        $ ansible-galaxy collection install infoblox-nios_modules-<version>.tar.gz -p ./collections
        ```

Please refer to our Ansible [deployment 
guide](https://www.infoblox.com/wp-content/uploads/infoblox-deployment-guide-automate-infoblox-infrastructure-using-ansible.pdf)
for more details.

Playbooks
=========
Latest sample playbooks and examples are available at [playbooks](https://github.com/infobloxopen/infoblox-ansible/tree/master/playbooks).


Releasing
=========

Next release
---------------

Dates TBD

Current release
---------------

1.5.0 on 11 May 2023

Versioning
=========

-   galaxy.yml in the master branch will always contain the version of the current major or minor release. It will be updated right after a release.
-   version_added needs to be used for every new feature and module/plugin, and needs to coincide with the next minor/major release version. (This will eventually be enforced by CI.)

Deprecation
===========
-   Deprecations are done by version number (not by date).
-   New deprecations can be added during every minor release, under the condition that they do not break backward compatibility.

Contributing
============
We welcome your contributions to Infoblox Nios Modules. See 
[CONTRIBUTING.md](https://github.com/infobloxopen/infoblox-ansible/blob/master/CONTRIBUTING.md) for
more details.

Resources
=========

-   Infoblox [NIOS
    modules](https://docs.ansible.com/ansible/latest/scenario_guides/guide_infoblox.html)
    on Ansible documentation

-   Infoblox [workspace](https://galaxy.ansible.com/infoblox) in Ansible
    Galaxy

-   Infoblox Ansible [deployment
    guide](https://www.infoblox.com/wp-content/uploads/infoblox-deployment-guide-automate-infoblox-infrastructure-using-ansible.pdf)

License
=======

This code is published under `GPL v3.0`

[COPYING](https://github.com/infobloxopen/infoblox-ansible/blob/master/COPYING)

Issues or RFEs
===============
You can open an issue or request for enhancement
[here](https://github.com/infobloxopen/infoblox-ansible/issues)

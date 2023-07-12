Ansible Network Collection for Enterprise SONiC Distribution by Dell Technologies
=================================================================================

This collection includes Ansible core modules, network resource modules, and plugins needed to provision and manage Dell EMC PowerSwitch platforms running Enterprise SONiC Distribution by Dell Technologies. Sample playbooks and documentation are also included to show how the collection can be used.

Supported connections
---------------------
The SONiC Ansible collection supports network_cli and httpapi connections.

Plugins
--------
**CLICONF plugin**

Name | Description
--- | ---
[network_cli](https://github.com/ansible-collections/dellemc.enterprise_sonic)|Use Ansible CLICONF to run commands on Enterprise SONiC

**HTTPAPI plugin**

Name | Description
--- | ---
[httpapi](https://github.com/ansible-collections/dellemc.enterprise_sonic)|Use Ansible HTTPAPI to run commands on Enterprise SONiC

Collection core modules
------------------------
Name | Description | Connection type
--- | --- | ---
[**sonic_command**](https://docs.ansible.com/ansible/latest/collections/dellemc/enterprise_sonic/sonic_command_module.html#ansible-collections-dellemc-enterprise-sonic-sonic-command-module)|Run commands through the Management Framework CLI|network_cli
[**sonic_config**](https://docs.ansible.com/ansible/latest/collections/dellemc/enterprise_sonic/sonic_config_module.html#ansible-collections-dellemc-enterprise-sonic-sonic-config-module)|Manage configuration through the Management Framework CLI|network_cli
[**sonic_api**](https://docs.ansible.com/ansible/latest/collections/dellemc/enterprise_sonic/sonic_api_module.html#ansible-collections-dellemc-enterprise-sonic-sonic-api-module)|Perform REST operations through the Management Framework REST API|httpapi

Collection network resource modules
-----------------------------------
Listed are the SONiC Ansible network resource modules which need ***httpapi*** as the connection type. Supported operations are ***merged*** and ***deleted***.

| **Interfaces** | **BGP** | **VRF** | **Users** |
| -------------- | ------- | ------- | ------- |
| [**sonic_interfaces**](https://docs.ansible.com/ansible/latest/collections/dellemc/enterprise_sonic/sonic_interfaces_module.html#ansible-collections-dellemc-enterprise-sonic-sonic-interfaces-module)|[**sonic_bgp**](https://docs.ansible.com/ansible/latest/collections/dellemc/enterprise_sonic/sonic_bgp_module.html#ansible-collections-dellemc-enterprise-sonic-sonic-bgp-module)| [**sonic_vrfs**](https://docs.ansible.com/ansible/latest/collections/dellemc/enterprise_sonic/sonic_vrfs_module.html#ansible-collections-dellemc-enterprise-sonic-sonic-vrfs-module)|[**sonic_users**](https://docs.ansible.com/ansible/latest/collections/dellemc/enterprise_sonic/sonic_users_module.html#ansible-collections-dellemc-enterprise-sonic-sonic-users-module)|
| [**sonic_l2_interfaces**](https://docs.ansible.com/ansible/latest/collections/dellemc/enterprise_sonic/sonic_l2_interfaces_module.html#ansible-collections-dellemc-enterprise-sonic-sonic-l2-interfaces-module)| [**sonic_bgp_af**](https://docs.ansible.com/ansible/latest/collections/dellemc/enterprise_sonic/sonic_bgp_af_module.html#ansible-collections-dellemc-enterprise-sonic-sonic-bgp-af-module)| **MCLAG** | **AAA** |
| [**sonic_l3_interfaces**](https://docs.ansible.com/ansible/latest/collections/dellemc/enterprise_sonic/sonic_l3_interfaces_module.html#ansible-collections-dellemc-enterprise-sonic-sonic-l3-interfaces-module) |[**sonic_bgp_as_paths**](https://docs.ansible.com/ansible/latest/collections/dellemc/enterprise_sonic/sonic_bgp_as_paths_module.html#ansible-collections-dellemc-enterprise-sonic-sonic-bgp-as-paths-module)| [**sonic_mclag**](https://docs.ansible.com/ansible/latest/collections/dellemc/enterprise_sonic/sonic_mclag_module.html#ansible-collections-dellemc-enterprise-sonic-sonic-mclag-module)| [**sonic_aaa**](https://docs.ansible.com/ansible/latest/collections/dellemc/enterprise_sonic/sonic_aaa_module.html#ansible-collections-dellemc-enterprise-sonic-sonic-aaa-module)|
|**Port channel**|[**sonic_bgp_communities**](https://docs.ansible.com/ansible/latest/collections/dellemc/enterprise_sonic/sonic_bgp_communities_module.html#ansible-collections-dellemc-enterprise-sonic-sonic-bgp-communities-module)| **VxLANs** |[**sonic_tacacs_server**](https://docs.ansible.com/ansible/latest/collections/dellemc/enterprise_sonic/sonic_tacacs_server_module.html#ansible-collections-dellemc-enterprise-sonic-sonic-tacacs-server-module)|
|[**sonic_lag_interfaces**](https://docs.ansible.com/ansible/latest/collections/dellemc/enterprise_sonic/sonic_lag_interfaces_module.html#ansible-collections-dellemc-enterprise-sonic-sonic-lag-interfaces-module)|[**sonic_bgp_ext_communities**](https://docs.ansible.com/ansible/latest/collections/dellemc/enterprise_sonic/sonic_bgp_ext_communities_module.html#ansible-collections-dellemc-enterprise-sonic-sonic-bgp-ext-communities-module)| [**sonic_vxlans**](https://docs.ansible.com/ansible/latest/collections/dellemc/enterprise_sonic/sonic_vxlans_module.html#ansible-collections-dellemc-enterprise-sonic-sonic-vxlans-module)|[**sonic_radius_server**](https://docs.ansible.com/ansible/latest/collections/dellemc/enterprise_sonic/sonic_radius_server_module.html#ansible-collections-dellemc-enterprise-sonic-sonic-radius-server-module)|
|**VLANs**|[**sonic_bgp_neighbors**](https://docs.ansible.com/ansible/latest/collections/dellemc/enterprise_sonic/sonic_bgp_neighbors_module.html#ansible-collections-dellemc-enterprise-sonic-sonic-bgp-neighbors-module)| **Port breakout** | **System** |
|[**sonic_vlans**](https://docs.ansible.com/ansible/latest/collections/dellemc/enterprise_sonic/sonic_vlans_module.html#ansible-collections-dellemc-enterprise-sonic-sonic-vlans-module)|[**sonic_bgp_neighbors_af**](https://docs.ansible.com/ansible/latest/collections/dellemc/enterprise_sonic/sonic_bgp_neighbors_af_module.html#ansible-collections-dellemc-enterprise-sonic-sonic-bgp-neighbors-af-module)|[**sonic_port_breakout**](https://docs.ansible.com/ansible/latest/collections/dellemc/enterprise_sonic/sonic_port_breakout_module.html#ansible-collections-dellemc-enterprise-sonic-sonic-port-breakout-module) |[**sonic_system**](https://docs.ansible.com/ansible/latest/collections/dellemc/enterprise_sonic/sonic_system_module.html#ansible-collections-dellemc-enterprise-sonic-sonic-system-module) |

Sample use case playbooks
-------------------------
The playbooks directory includes this sample playbook that show end-to-end use cases.

Name | Description
--- | ---
[**BGP Layer 3 fabric**](https://github.com/ansible-collections/dellemc.enterprise_sonic/tree/master/playbooks/bgp_l3_fabric)|Example playbook to build a Layer 3 leaf-spine fabric

Version compatibility
----------------------
* Recommended Ansible version 2.10 or higher
* Enterprise SONiC Distribution by Dell Technologies version 3.1 or higher
* Recommended Python 3.5 or higher, or Python 2.7
* Dell Enterprise SONiC images for releases 3.1 - 3.5: Use Ansible Enterprise SONiC collection version 1.1.0 or later 1.m.n versions (from the 1.x branch of this repo)
* Dell Enterprise SONiC images for release 4.0 and later 4.x.y releases: Use Ansible Enterprise SONiC collection version 2.0.0 or later 2.m.n releases (from the "2.x" branch of this repo).
* In general:  Dell Enterprise SONiC release versions "R.x.y" are supported by Ansible Enterprise SONiC collection versions "R-2.m.n" on branch "R-2.x".


> **NOTE**: Community SONiC versions that include the Management Framework container should work as well, however, this collection has not been tested nor validated 
        with community versions and is not supported.

Installation of Ansible 2.11+
-----------------------------
##### Dependencies for Ansible Enterprise SONiC collection

      pip3 install paramiko>=2.7
      pip3 install jinja2>=2.8
      pip3 install ansible-core

Installation of Ansible 2.10+
-----------------------------
##### Dependencies for Ansible Enterprise SONiC collection

      pip3 install paramiko>=2.7
      pip3 install jinja2>=2.8
      pip3 install ansible-base
      
      
Installation of Ansible 2.9
---------------------------
##### Dependencies for Ansible Enterprise SONiC collection

      pip3 install paramiko>=2.7
      pip3 install jinja2>=2.8
      pip3 install ansible
      
##### Setting Environment Variables

To use the Enterprise SONiC collection in Ansible 2.9, it is required to add one of the two available environment variables.

Option 1: Add the environment variable while running the playbook.


      ANSIBLE_NETWORK_GROUP_MODULES=sonic ansible-playbook sample_playbook.yaml -i inventory.ini
      
      
Option 2: Add the environment variable in user profile.


      ANSIBLE_NETWORK_GROUP_MODULES=sonic
      

Installation of Enterprise SONiC collection from Ansible Galaxy
---------------------------------------------------------------

Install the latest version of the Enterprise SONiC collection from Ansible Galaxy.

      ansible-galaxy collection install dellemc.enterprise_sonic

To install a specific version, specify a version range identifier. For example, to install the most recent version that is greater than or equal to 1.0.0 and less than 2.0.0.

      ansible-galaxy collection install 'dellemc.enterprise_sonic:>=1.0.0,<2.0.0'


Sample playbooks
-----------------
**VLAN configuration using CLICONF**

***sonic_network_cli.yaml***

    ---

    - name: SONiC Management Framework CLI configuration examples
      hosts: sonic_switches
      gather_facts: no
      connection: network_cli
      tasks:
        - name: Add VLAN entry
          dellemc.enterprise_sonic.sonic_config:
            commands: ['interface Vlan 700','exit']
            save: yes
          register: config_op
        - name: Test SONiC single command
          dellemc.enterprise_sonic.sonic_command:
            commands: 'show vlan'
          register: cmd_op

**VLAN configuration using HTTPAPI**

***sonic_httpapi.yaml***

    ---

    - name: SONiC Management Framework REST API examples
      hosts: sonic_switches
      gather_facts: no
      connection: httpapi
      tasks:
        - name: Perform PUT operation to add a VLAN network instance
          dellemc.enterprise_sonic.sonic_api:
            url: data/openconfig-network-instance:network-instances/network-instance=Vlan100
            method: "PUT"
            body: {"openconfig-network-instance:network-instance": [{"name": "Vlan100","config": {"name": "Vlan100"}}]}
            status_code: 204
        - name: Perform GET operation to view VLAN network instance
          dellemc.enterprise_sonic.sonic_api:
            url: data/openconfig-network-instance:network-instances/network-instance=Vlan100
            method: "GET"
            status_code: 200
          register: api_op

**Configuration using network resource modules**

***sonic_resource_modules.yaml***

    ---

    - name: VLANs, Layer 2 and Layer 3 interfaces configuration using Enterprise SONiC resource modules
      hosts: sonic_switches
      gather_facts: no
      connection: httpapi
      tasks:
       - name: Configure VLANs
         dellemc.enterprise_sonic.sonic_vlans:
            config:
             - vlan_id: 701
             - vlan_id: 702
             - vlan_id: 703
             - vlan_id: 704
            state: merged
         register: sonic_vlans_output
       - name: Configure Layer 2 interfaces
         dellemc.enterprise_sonic.sonic_l2_interfaces:
            config:
            - name: Eth1/2
              access:
                vlan: 701
              trunk:
                allowed_vlans:
                  - vlan: 702
                  - vlan: 703
            state: merged
         register: sonic_l2_interfaces_output
       - name: Configure Layer 3 interfaces
         dellemc.enterprise_sonic.sonic_l3_interfaces:
           config:
            - name: Eth1/3
              ipv4:
                - address: 8.1.1.1/16
              ipv6:
                - address: 3333::1/16
           state: merged
         register: sonic_l3_interfaces_output

***host_vars/sonic_sw1.yaml***

    hostname: sonic_sw1

    # Common parameters for connection type httpapi or network_cli:
    ansible_user: xxxx
    ansible_pass: xxxx
    ansible_network_os: dellemc.enterprise_sonic.sonic

    # Additional parameters for connection type httpapi:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false

***inventory.ini***

    [sonic_sw1]
    sonic_sw1 ansible_host=100.104.28.119

    [sonic_sw2]
    sonic_sw2 ansible_host=100.104.28.120

    [sonic_switches:children]
    sonic_sw1
    sonic_sw2

Releasing, Versioning and Deprecation
-------------------------------------

This collection follows [Semantic Versioning](https://semver.org/). More details on versioning can be found [in the Ansible docs](https://docs.ansible.com/ansible/latest/dev_guide/developing_collections.html#collection-versions).

We plan to regularly release new minor or bugfix versions once new features or bugfixes have been implemented.

Enterprise SONiC Ansible Modules deprecation cycle is aligned with [Ansible](https://docs.ansible.com/ansible/latest/dev_guide/module_lifecycle.html).

Source control branches on Github:
  - Released code versions are located on "release" branches with names of the form "M.x", where "M" specifies the "major" release version for releases residing on the branch.
  - Unreleased and pre-release code versions are located on sub-branches of the "main" branch. This is a development branch, and is not intended for use in production environments.

Code of Conduct
---------------

This repository adheres to the [Ansible Community code of conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html)

(c) 2020-2021 Dell Inc. or its subsidiaries. All Rights Reserved.

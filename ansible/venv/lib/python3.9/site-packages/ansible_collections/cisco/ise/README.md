# Ansible Collection - cisco.ise

## Ansible Modules for Cisco ISE

The ise-ansible project provides an Ansible collection for managing and automating your Cisco Identity Services Engine (ISE) environment. It consists of a set of modules and roles for performing tasks related to Cisco ISE.

This collection has been validated with Cisco ISE 3.1 + Patch 1.

These Ansible modules will work with any version of ISE that supports the underlying REST API resources you want to configure. Please see the [ISE API Versioning](https://developer.cisco.com/docs/identity-services-engine/v1/#!versioning) reference for which REST Resources were first supported in which Cisco ISE Version.

*Note: This collection is not compatible with versions of Ansible before v2.9.*

Other versions of this collection have support for previous Cisco ISE versions. The recommended versions are listed on the [Compatibility matrix](https://github.com/CiscoISE/ansible-ise#compatibility-matrix).

## Requirements
- Ansible >= 2.9
- [Cisco ISE SDK](https://github.com/CiscoISE/ciscoisesdk) v1.4.0 or newer
- Python >= 3.6, as the Cisco ISE SDK doesn't support Python version 2.x
- requests >= 2.25.1, for the personas modules and personas_deployment role.

## Install
Ansible must be installed ([Install guide](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html))
```
sudo pip install ansible
```

Cisco ISE SDK must be installed
```
sudo pip install ciscoisesdk
```

Install the collection ([Galaxy link](https://galaxy.ansible.com/cisco/ise))
```
ansible-galaxy collection install cisco.ise
```
## ISE Setup

This collection assumes that the API Gateway, the ERS APIs and OpenAPIs are enabled.

### Using the collection on previous Cisco ISE versions 

As stated before, the collection has been tested and supports Cisco ISE 3.1_Patch_1.

It may work with Cisco ISE version 3.0, but it is not officially supported.

The recommended versions are listed below on the [Compatibility matrix](https://github.com/CiscoISE/ansible-ise#compatibility-matrix).

## Compatibility matrix
The following table shows the supported versions.
| Cisco ISE version | Ansible "cisco.ise" version  | Python "ciscoisesdk" version |
|-------------------|------------------------------|------------------------------|
| 3.1.0             | 2.0.0                        | 1.2.0                        |
| 3.1_Patch_1       | 2.5.12                        | 2.0.8                        |

If your Ansible collection is older please consider updating it first.
*Notes*:

1. The "Python 'ciscoisesdk' version" column has the minimum recommended version used when testing the Ansible collection. This means you could use later versions of the Python "ciscoisesdk" than those listed.
2. The "Cisco ISE version" column has the value of the `ise_version` you should use for the Ansible collection.

## Installing according to Compatibility Matrix

For example, for Cisco ISE 3.1.0, it is recommended to use Ansible "cisco.ise" v2.0.0 and Python "ciscoisesdk" v1.2.0.

To get the Python Cisco ISE SDK v1.2.0 in a fresh development environment:
```
sudo pip install ciscoisesdk==1.2.0
```

To get the Ansible collection v2.0.0 in a fresh development environment:
```
ansible-galaxy collection install cisco.ise:2.0.0
```


## Using this collection

There are three ways to use it:
- [Using environment variables](#using-environment-variables)
- [Using vars_files](#using-vars_files)
- [Using group_vars directory](#using-group_vars-directory)

### Using environment variables
First, export the environment variables where you specify your Cisco ISE credentials as ansible variables:
```
export ISE_HOSTNAME=<A.B.C.D>
export ISE_USERNAME=<username>
export ISE_PASSWORD=<password>
export ISE_VERIFY=False # optional, defaults to True
export ISE_VERSION=3.1_Patch_1 # optional, defaults to 3.1_Patch_1
export ISE_WAIT_ON_RATE_LIMIT=True # optional, defaults to True
export ISE_USES_API_GATEWAY=True # optional, defaults to True
export ISE_DEBUG=False # optional, defaults to False
```

Create a `hosts` ([example](https://github.com/CiscoISE/ansible-ise/blob/main/playbooks/hosts)) file that uses `[ise_servers]` with your Cisco ISE Settings:
```
[ise_servers]
ise_server
```

Then, create a playbook `myplaybook.yml` ([example](https://github.com/CiscoISE/ansible-ise/blob/main/playbooks/network_device.yml)) specifying the full namespace path to the module, plugin and/or role:
```
- hosts: ise_servers
  gather_facts: no
  tasks:
  - name: Get network device by id
    cisco.ise.network_device_info:
      id: "0667bc80-78a9-11eb-b987-005056aba98b"
```

Execute the playbook:
```
ansible-playbook -i hosts myplaybook.yml
```

### Using vars_files

First, define a `credentials.yml` ([example](https://github.com/CiscoISE/ansible-ise/blob/main/playbooks/credentials.template)) file where you specify your Cisco ISE credentials as ansible variables:
```
---
ise_hostname: <A.B.C.D>
ise_username: <username>
ise_password: <password>
ise_verify: False # optional, defaults to True
ise_version: 3.1_Patch_1 # optional, defaults to 3.1_Patch_1
ise_wait_on_rate_limit: True # optional, defaults to True
ise_debug: False # optional, defaults to False
ise_uses_api_gateway: True # optional, defaults to True
ise_uses_csrf_token: False # optional, defaults to False
```

Create a `hosts` ([example](https://github.com/CiscoISE/ansible-ise/blob/main/playbooks/hosts)) file that uses `[ise_servers]` with your Cisco ISE Settings:
```
[ise_servers]
ise_server
```

Then, create a playbook `myplaybook.yml` referencing the variables in your credentials.yml file and specifying the full namespace path to the module, plugin and/or role:
```
- hosts: ise_servers
  vars_files:
    - credentials.yml
  gather_facts: no
  tasks:
  - name: Get network device by id
    cisco.ise.network_device_info:
      ise_hostname: "{{ise_hostname}}"
      ise_username: "{{ise_username}}"
      ise_password: "{{ise_password}}"
      ise_verify: "{{ise_verify}}"
      ise_debug: "{{ise_debug}}"
      ise_uses_api_gateway: "{{ise_uses_api_gateway}}"
      ise_uses_csrf_token: "{{ise_uses_csrf_token}}"
      id: "0667bc80-78a9-11eb-b987-005056aba98b"
```

Execute the playbook:
```
ansible-playbook -i hosts myplaybook.yml
```
In the `playbooks` [directory](https://github.com/CiscoISE/ansible-ise/tree/main/playbooks) directory you can find more examples and use cases.

**Note**: The examples found on the `playbooks` directory use the `group_vars` variables. Remember to make the appropiate changes when running the examples.

### Using group_vars directory

First, define your group_vars for credentials `ise_servers` ([example](https://github.com/CiscoISE/ansible-ise/blob/main/playbooks/group_vars/ise_servers)) file where you specify your Cisco ISE credentials as ansible variables:
```
---
ise_hostname: <A.B.C.D>
ise_username: <username>
ise_password: <password>
ise_verify: False # optional, defaults to True
ise_version: 3.1_Patch_1 # optional, defaults to 3.1_Patch_1
ise_wait_on_rate_limit: True # optional, defaults to True
ise_debug: False # optional, defaults to False
ise_uses_api_gateway: True # optional, defaults to True
ise_uses_csrf_token: False # optional, defaults to False
```

Create a `hosts` ([example](https://github.com/CiscoISE/ansible-ise/blob/main/playbooks/hosts)) file that uses `[ise_servers]` with your Cisco ISE Settings:
```
[ise_servers]
ise_server
```

Then, create a playbook `myplaybook.yml` ([example](https://github.com/CiscoISE/ansible-ise/blob/main/playbooks/network_device.yml)) referencing the variables in your `group_vars/ise_servers` file and specifying the full namespace path to the module, plugin and/or role:
```
- hosts: ise_servers
  gather_facts: no
  tasks:
  - name: Get network device by id
    cisco.ise.network_device_info:
      ise_hostname: "{{ise_hostname}}"
      ise_username: "{{ise_username}}"
      ise_password: "{{ise_password}}"
      ise_verify: "{{ise_verify}}"
      ise_debug: "{{ise_debug}}"
      ise_uses_api_gateway: "{{ise_uses_api_gateway}}"
      ise_uses_csrf_token: "{{ise_uses_csrf_token}}"
      id: "0667bc80-78a9-11eb-b987-005056aba98b"
```

Execute the playbook:
```
ansible-playbook -i hosts myplaybook.yml
```
In the `playbooks` [directory](https://github.com/CiscoISE/ansible-ise/tree/main/playbooks)  directory you can find more examples and use cases.

**Note**: The examples found on the `playbooks` directory use the `group_vars` variables. Consider using `ansible-vault` to encrypt the file that has the `ise_username` and `ise_password`.


## Update
Getting the latest/nightly collection build

Clone the ansible-ise repository.
```
git clone https://github.com/CiscoISE/ansible-ise.git
```

Go to the ansible-ise directory
```
cd ansible-ise
```

Pull the latest master from the repo
```
git pull origin master
```

Build and install a collection from source
```
ansible-galaxy collection build --force
ansible-galaxy collection install cisco-ise-* --force
```

### See Also:

* [Ansible Using collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html) for more details.

## Attention macOS users

If you're using macOS you may receive this error when running your playbook:

```
objc[34120]: +[__NSCFConstantString initialize] may have been in progress in another thread when fork() was called.
objc[34120]: +[__NSCFConstantString initialize] may have been in progress in another thread when fork() was called. We cannot safely call it or ignore it in the fork() child process. Crashing instead. Set a breakpoint on objc_initializeAfterForkError to debug.
ERROR! A worker was found in a dead state
```

If that's the case try setting these environment variables:
```
export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
export no_proxy=*
```

## Contributing to this collection

Ongoing development efforts and contributions to this collection are tracked as issues in this repository.

We welcome community contributions to this collection. If you find problems, need an enhancement or need a new module, please open an issue or create a PR against the [Cisco ISE Ansible collection repository](https://github.com/CiscoISE/ansible-ise/issues).

## Code of Conduct
This collection follows the Ansible project's
[Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html).
Please read and familiarize yourself with this document.

## Releasing, Versioning and Deprecation

This collection follows [Semantic Versioning](https://semver.org/). More details on versioning can be found [in the Ansible docs](https://docs.ansible.com/ansible/latest/dev_guide/developing_collections.html#collection-versions).

New minor and major releases as well as deprecations will follow new releases and deprecations of the Cisco ISE product, its REST API and the corresponding Python SDK, which this project relies on. 

# ansible-nso

The ansible-nso project provides an Ansible collection for managing and automating your Cisco NSO environment. It consists of a set of modules and roles for performing tasks in NSO.

This collection has been tested and supports version 5.3+ of NSO.

*Note: This collection is not compatible with versions of Ansible before v2.9.

## Requirements
Ansible v2.9 or newer

## Install
Ansible must be installed
```
sudo pip install ansible
```

Install the collection
```
ansible-galaxy collection install cisco.nso
```
## Use
Once the collection is installed, you can use it in a playbook by specifying the full namespace path to the module, plugin and/or role.

```yaml
- hosts: nso
  gather_facts: no

  tasks:
    - name: CREATE DEVICE IN NSO
      cisco.nso.nso_config:
        url: https://10.10.20.49/jsonrpc
        username: developer
        password: C1sco12345
        data:
          tailf-ncs:devices:
            device:
            - address: 10.10.20.175
              description: CONFIGURED BY ANSIBLE!
              name: dist-rtr01
              authgroup: "labadmin"
              device-type:
                cli:
                  ned-id: "cisco-ios-cli-6.44"
              port: "22"
              state:
                admin-state: "unlocked"
```

## Update
Getting the latest/nightly collection build

### First Approach
Clone the ansible-nso repository.
```
git clone https://github.com/CiscoDevNet/ansible-nso.git
```

Go to the ansible-nso directory
```
cd ansible-nso
```

Pull the latest master on your NSO
```
git pull origin master
```

Build and Install a collection from source
```
ansible-galaxy collection build --force
ansible-galaxy collection install cisco-nso-* --force
```

### See Also:

* [Ansible Using collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html) for more details.

## Contributing to this collection

Ongoing development efforts and contributions to this collection are tracked as issues in this repository.

We welcome community contributions to this collection. If you find problems, need an enhancement or need a new module, please open an issue or create a PR against the [Cisco NSO collection repository](https://github.com/CiscoDevNet/ansible-nso/issues).
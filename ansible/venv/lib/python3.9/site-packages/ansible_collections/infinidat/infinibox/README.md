# Infinidat's Ansible Collection

## Platforms Supported
All Infindat InfiniBoxes are supported.

## Prerequisites
- Ansible 2.12 or newer
- InfiniSDK 151.1.1 or newer.

## Modules
- infini_cluster: Creates, deletes or modifies host clusters.
- infini_export_client: Creates, deletes or modifys NFS client(s) for existing exports.
- infini_export: Creates, deletes or modifies NFS exports.
- infini_fs: Creates, deletes or modifies filesystems.
- infini_host: Creates, deletes or modifies hosts.
- infini_map: Creates or deletes mappings of volumes to hosts.
- infini_pool: Creates, deletes or modifies pools.
- infini_port: Adds or deletes fiber channel or iSCSI ports to hosts.
- infini_user: Creates, deletes or modifies an InfiniBox user.
- infini_vol: Creates, deletes or modifies a volume.

Most modules also implement a "stat" state.  This is used to gather information, aka status, for the resource without making any changes to it.

## Installation
Install the Infinidat Ansible collection on hosts or within containers using:
`ansible-galaxy collection install infinidat.infibox -p ~/.ansible/collections`

Complete instructions for installing collections is available at https://docs.ansible.com/ansible/latest/user_guide/collections_using.html.

Ansible 2.9 or newer is required to install as a collection.  That said, the collection is a tarball.  Modules may be extracted and installed manually if use of an older version of Ansible is required.  Adjust values in playbooks/ansible.cfg as required. 

## Usage
A Makefile is provided. To see the recipes available within it use `make help`.

Example playbooks are included in the collection:

- Main test playbooks:
    - test_create_resources.yml: A playbook that creates many resources. It also creates resources again to test idempotency.
    - test_remove_resources.yml: A playbook that in the end removes the resources created in the test_create_resources playbook. It too will test idempotency by removing resources again.

- Playbooks for testing cluster mapping:
    - test_create_map_cluster.yml: Creates a cluster with hosts and tests mapping a volume to the cluster and hosts.
    - test_remove_map_cluster.yml: Removes resouces created by its cohort.

- Playbooks for testing snapshotting:

These two playbooks serve as a reference to the use of the modules. These exercise all modules demonstrating normal usage, idempotency and error conditions. Individual module documentation is available via `ansible-doc`.

### Example Usage
Install the collection and cd into the collection's infi/ directory.  Create an ibox yaml file in ibox_vars/.  Use the example yaml file as a reference.

The `--ask-vault-pass` options below are only required if the ibox_vars/iboxNNNN.yaml file is encrypted using ansible-vault.
```
sudo apt install python3.8 python3.8-venv python3.8-distutils libffi-dev
python3.8 -m venv venv
source venv/bin/activate
python -m pip install -U pip
python -m pip install -r requirements.txt
cd playbooks/
../venv/bin/ansible-playbook --extra-vars "@../ibox_vars/iboxNNNN.yaml" --ask-vault-pass test_create_resources.yml
../venv/bin/ansible-playbook --extra-vars "@../ibox_vars/iboxNNNN.yaml" --ask-vault-pass test_remove_resources.yml
deactivate
```

## Removal
To remove the collection, delete the collection from the path specified in the -p option during installation.

## Copyrights and Licenses
- Copyright: (c) 2020, Infinidat <info@infinidat.com>
- GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

## Authors
The initial set of Infindat Ansible modules were written by Gregory Shulov in 2016.

Infinidat's Professional Services (USA) team extended and improved the modules in 2019. Several modules were added. Idempotency was improved.

## Pull requests and feature requests
Contributions will be considered via standard Git processes. If you choose to contribute, such contribution must be permanently licensed in line with the overall project license, and copyright and all other IP rights for your contribution must be permanently assigned to Infinidat and/or its successors.

# F5 BIG-IP Imperative Collection for Ansible

This collection includes imperative Ansible modules for BIG-IP and BIG-IQ from F5 Networks.
This collection packages and distributes modules, and plugins.

## Requirements

 - ansible >= 2.9
 - packaging

## Python Version Notice
Collection only supports python 3.6 and above, however F5 recommends Python 3.8 and above.

## Installation
To install in ansible default or defined paths use:
```bash
ansible-galaxy collection install f5networks.f5_modules
```

To specify the installation location use `-p`. If specifying a folder, make sure to update the `ansible.cfg` so ansible will check this folder as well.
```bash
ansible-galaxy collection install f5networks.f5_modules -p collections/
```

To specify the version of the collection to install, include it at the end of the collection with `:==1.0.0`:
```bash
ansible-galaxy collection install f5networks.f5_modules:==1.0.0
```

Semantic Versioning examples below:
- Increment major (for example: x in x.y.z) version number for an incompatible API change.
- Increment minor (for example: y in x.y.z) version number for new functionality in a backwards compatible manner.
- Increment patch (for example: z in x.y.z) version number for backwards compatible bug fixes.

## Example Usage

To use a module from a collection, reference the full namespace, collection, and modules name that you want to use:

```
---
- name: Using Collections
  hosts: f5
  connection: local

  tasks:
    - f5networks.f5_modules.bigip_pool:
        name: my-pool
        ....

```

## Collections Daily Build

We offer a daily build of our most recent collection [dailybuild]. Use this Collection to test the most
recent Ansible module updates between releases. You can also install development build directly from GitHub see [repoinstall].

### Install from GitHub
```bash

ansible-galaxy collection install git+https://github.com/F5Networks/f5-ansible-bigip.git#ansible_collections/f5networks/f5_bigip
```

### Install from the daily build file
```bash

    ansible-galaxy collection install <collection name> -p ./collections
    e.g.
    ansible-galaxy collection install f5networks-f5_modules-devel.tar.gz -p ./collections
```

> **_NOTE:_**  `-p` is the location in which the collection will be installed. This location should be defined in the path for
    Ansible to search for collections. An example of this would be adding ``collections_paths = ./collections``
    to your **ansible.cfg**

### Running latest devel in EE
We also offer a new method of running the collection inside Ansible's Execution Environment container. 
The advantage of such approach is that any required package dependencies and minimum supported pyton versions are 
installed in an isolated container which minimizes any environment related issues during runtime. More information on EE
can be found here [execenv]. Use the below requirements.yml file when building EE container:

```yaml
---
collections:
  - name: ansible.netcommon
    version: ">=2.0.0"
  - name: f5networks.f5_modules
    source: https://github.com/F5Networks/f5-ansible-f5modules#ansible_collections/f5networks/f5_modules
    type: git
    version: devel
```

Please see [f5execenv] documentation for further instructions how to use and build EE container with our devel branch.


## Author Information

F5 Networks
[F5 Networks](http://www.f5.com)


[repoinstall]: https://docs.ansible.com/ansible/latest/user_guide/collections_using.html#installing-a-collection-from-a-git-repository
[dailybuild]: https://f5-ansible.s3.amazonaws.com/collections/f5networks-f5_modules-devel.tar.gz
[execenv]: https://docs.ansible.com/automation-controller/latest/html/userguide/execution_environments.html
[f5execenv]: http://clouddocs.f5.com/products/orchestration/ansible/devel/usage/exec-env.html

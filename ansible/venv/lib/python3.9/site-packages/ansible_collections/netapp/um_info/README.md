[![Documentation](https://img.shields.io/badge/docs-brightgreen.svg)](https://docs.ansible.com/ansible/devel/collections/netapp/um_info/index.html)
![example workflow](https://github.com/ansible-collections/netapp.um_info/actions/workflows/main.yml/badge.svg)
[![codecov](https://codecov.io/gh/ansible-collections/netapp.um_info/branch/main/graph/badge.svg?token=weBYkksxSi)](https://codecov.io/gh/ansible-collections/netapp.um_info)


=============================================================

 netapp.um_info

 NetApp Unified Manager(AIQUM 9.7) Collection

 Copyright (c) 2020 NetApp, Inc. All rights reserved.
 Specifications subject to change without notice.

=============================================================
# Installation
```bash
ansible-galaxy collection install netapp.um_info
```
To use Collection add the following to the top of your playbook, with out this you will be using Ansible 2.9 version of the module
```
collections:
  - netapp.um_info
```

# Module documentation
https://docs.ansible.com/ansible/devel/collections/netapp/um_info/

# Code of Conduct
This collection follows the [Ansible project's Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html).

# Need help
Join our Slack Channel at [Netapp.io](http://netapp.io/slack)

# Release Notes

## 21.8.0

#### Minor changes
  - all modules - enable usage of Ansible module group defaults - for Ansible 2.12+.

## 21.7.0

#### Minor changes
  - all modules - ability to trace API calls and responses.
  - all modules - new `max_records` option to limit the amount of data in a single GET response.

### Bux fixes
  - all modules - report error when connecting to a server that does not run AIQUM.
  - all modules - return all records rather than the first 1000 records (mostly for volumes).
  - rename na_um_list_volumes.p to na_um_list_volumes.py.

## 21.6.0
### Minor changes
- na_um_list_aggregates has been renamed na_um_aggregates_info 
- na_um_list_clusters has been renamed na_um_clusters_info
- na_um_list_nodes has been renamed na_um_nodes_info
- na_um_list_svms has been renamed na_um_svms_info
- na_um_list_volumes has been renamed na_um_volumes_info

## 21.5.0

### Minor changes
- minor changes to meet Red Hat requirements to be certified.

## 20.7.0

### Minor changes
- na_um_list_aggregates: Now sort by performance_capacity.used
- na_um_list_nodes: Now sort by performance_capacity.used

## 20.6.0

### New Modules
- na_um_list_volumes: list volumes.

## 20.5.0

### New Modules
- na_um_list_aggregates: list aggregates.
- na_um_list_clusters: list clusters.
- na_um_list_nodes: list nodes.
- na_um_list_svms: list svms.

[![Documentation](https://img.shields.io/badge/docs-brightgreen.svg)](https://docs.ansible.com/ansible/devel/collections/netapp/aws/index.html)
![example workflow](https://github.com/ansible-collections/netapp.aws/actions/workflows/main.yml/badge.svg)
[![codecov](https://codecov.io/gh/ansible-collections/netapp.aws/branch/main/graph/badge.svg?token=weBYkksxSi)](https://codecov.io/gh/ansible-collections/netapp.aws)


=============================================================
                                                             
netapp.aws                                                   
                                                             
NetApp AWS CVS Collection                                    
                                                             
Copyright (c) 2019 NetApp, Inc. All rights reserved.         
Specifications subject to change without notice.             
                                                             
=============================================================

# Installation
```bash
ansible-galaxy collection install netapp.aws
```
To use Collection add the following to the top of your playbook, with out this you will be using Ansible 2.9 version of the module
```  
collections:
  - netapp.aws
```

# Module documentation
https://docs.ansible.com/ansible/devel/collections/netapp/aws/

# Need help
Join our Slack Channel at [Netapp.io](http://netapp.io/slack)

# Notes

These Ansible modules are supporting NetApp Cloud Volumes Service for AWS.

They require a subscription to the service and your API access keys.

The modules currently support Active Directory, Pool, FileSystem (Volume), and Snapshot services.

# Release Notes


## 21.7.0

### Minor Changes
- all modules - allow usage of Ansible module group defaults - for Ansible 2.12+.

## 21.6.0

### Minor Changes
- all modules - ability to trace API calls and responses.

### Bug Fixes
- all modules - fix traceback TypeError 'NoneType' object is not subscriptable when URL points to a web server.

## 21.2.0

### Bug Fixes
- aws_netapp_cvs_filesystems - fix KeyError when exportPolicy is not present.
- all modules - disable logging for `api_key` and `secret_key` values.
- all modules - report error if response does not contain valid JSON.
- all modules - prevent infinite loop when asynchornous action fails.

## 20.9.0

Fix pylint or flake8 warnings reported by galaxy importer.

## 20.8.0

### Module documentation changes
- use a three group format for `version_added`.  So 2.7 becomes 2.7.0.  Same thing for 2.8 and 2.9.
- add `elements:` and update `required:` to match module requirements.

## 20.6.0

### Bug Fixes
- galaxy.xml: fix repository and homepage links.

## 20.2.0

### Bug Fixes
- galaxy.yml: fix path to github repository.

## 19.11.0
- Initial release as a collection.

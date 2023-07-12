<!-- please note this has to be a absolute URL since otherwise it will not show up on galaxy.ansible.com -->
![cyberark logo|](https://github.com/cyberark/ansible-security-automation-collection/blob/master/docs/images/full-cyberark-logo.jpg?raw=true)

## CyberArk Ansible Security Automation Collection

*************

## Collection

#### cyberark.pas

This collection is the CyberArk Ansible Security Automation project and can be found on [ansible galaxy](https://galaxy.ansible.com/cyberark/pas). This is aimed to enable the automation of securing privileged access by storing privileged accounts in the Enterprise Password Vault (EPV), controlling user's access to privileged accounts in EPV, and securely retreiving secrets using Application Access Manager (AAM).
The collection includes [support for Event-Driven Ansible](https://github.com/cyberark/ansible-security-automation-collection/blob/master/docs/cyberark_eda.md) by providing an event-source plugin for syslog and also guidance on how to use it. 


The following modules will allow CyberArk administrators to automate the following tasks:

#### Requirements

- CyberArk Privileged Account Security Web Services SDK
- CyberArk AAM Central Credential Provider (**Only required for cyberark_credential**)

#### Role Variables

None.
<br>
<br>

## Modules

#### cyberark_authentication

- Using the CyberArk Web Services SDK, authenticate and obtain an auth token to be passed as a variable in playbooks
- Logoff of an authenticated REST API session<br>
[Playbooks and Module Info](https://github.com/cyberark/ansible-security-automation-collection/blob/master/docs/cyberark_authentication.md)

#### cyberark_user

- Add a CyberArk User
- Delete a CyberArk User
- Update a CyberArk User's account parameters
    - Enable/Disable, change password, mark for change at next login, etc
<br>[Playbooks and Module Info](https://github.com/cyberark/ansible-security-automation-collection/blob/master/docs/cyberark_user.md)<br/>

#### cyberark_account

- Add Privileged Account to the EPV
- Delete account objects
- Modify account properties
- Rotatate privileged credentials<br>
[Playbooks and Module Info](https://github.com/cyberark/ansible-security-automation-collection/blob/master/docs/cyberark_account.md)

#### cyberark_credential

- Using AAM Central Credential Provider (CCP), to securely retreive secrets and account properties from EPV to be registered for use in playbooks<br>
[Playbooks and Module Info](https://github.com/cyberark/ansible-security-automation-collection/blob/master/docs/cyberark_credential.md)

## Roles

#### aimprovider

- Install agent-based Credential Provider (AIM) on Linux hosts
[Playbooks and Module Info](https://github.com/cyberark/ansible-security-automation-collection/blob/master/docs/aimprovider.md)

#### Python3

- The modules will work with either python2 or python3.

#### Author Information
- CyberArk Business Development Technical Team 
    - @enunez-cyberark
    - @cyberark-bizdev


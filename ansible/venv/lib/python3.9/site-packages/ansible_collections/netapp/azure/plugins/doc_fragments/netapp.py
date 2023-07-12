# -*- coding: utf-8 -*-

# Copyright: (c) 2019, NetApp Ansible Team ng-ansibleteam@netapp.com
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class ModuleDocFragment(object):

    DOCUMENTATION = r'''
options:
  - See respective platform section for more details
requirements:
  - See respective platform section for more details
notes:
  - Ansible modules are available for the following NetApp Storage Platforms: E-Series, ONTAP, SolidFire
'''

    # Documentation fragment for Cloud Volume Services on Azure NetApp (azure_rm_netapp)
    AZURE_RM_NETAPP = r'''
options:
  resource_group:
      description:
      - Name of the resource group.
      required: true
      type: str
requirements:
    - python >= 2.7
    - azure >= 2.0.0
    - Python azure-mgmt. Install using 'pip install azure-mgmt'
    - Python azure-mgmt-netapp. Install using 'pip install azure-mgmt-netapp'
    - For authentication with Azure NetApp log in before you run your tasks or playbook with C(az login).

notes:
    - The modules prefixed with azure_rm_netapp are built to support the Cloud Volume Services for Azure NetApp Files.

seealso:
    - name: Sign in with Azure CLI
      link: https://docs.microsoft.com/en-us/cli/azure/authenticate-azure-cli?view=azure-cli-latest
      description: How to authenticate using the C(az login) command.
    '''

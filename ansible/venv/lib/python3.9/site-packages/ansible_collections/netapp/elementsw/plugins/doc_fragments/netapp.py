# -*- coding: utf-8 -*-

# Copyright: (c) 2018, NetApp Ansible Team <ng-ansibleteam@netapp.com>
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

    # Documentation fragment for SolidFire
    SOLIDFIRE = r'''
options:
  hostname:
      required: true
      description:
      - The hostname or IP address of the SolidFire cluster.
      - For na_elementsw_cluster, the Management IP (MIP) or hostname of the node to initiate the cluster creation from.
      type: str
  username:
      required: true
      description:
      - Please ensure that the user has the adequate permissions. For more information, please read the official documentation
        U(https://mysupport.netapp.com/documentation/docweb/index.html?productID=62636&language=en-US).
      aliases: ['user']
      type: str
  password:
      required: true
      description:
      - Password for the specified user.
      aliases: ['pass']
      type: str

requirements:
  - The modules were developed with SolidFire 10.1
  - solidfire-sdk-python (1.1.0.92) or greater. Install using 'pip install solidfire-sdk-python'

notes:
  - The modules prefixed with na\\_elementsw are built to support the SolidFire storage platform.

'''

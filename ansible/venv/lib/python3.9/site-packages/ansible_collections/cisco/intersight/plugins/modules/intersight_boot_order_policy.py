#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: intersight_boot_order_policy
short_description: Boot Order policy configuration for Cisco Intersight
description:
  - Boot Order policy configuration for Cisco Intersight.
  - Used to configure Boot Order servers and timezone settings on Cisco Intersight managed devices.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs).
extends_documentation_fragment: intersight
options:
  state:
    description:
      - If C(present), will verify the resource is present and will create if needed.
      - If C(absent), will verify the resource is absent and will delete if needed.
    choices: [present, absent]
    default: present
  organization:
    description:
      - The name of the Organization this resource is assigned to.
      - Profiles and Policies that are created within a Custom Organization are applicable only to devices in the same Organization.
    default: default
  name:
    description:
      - The name assigned to the Boot Order policy.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    required: true
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
  description:
    description:
      - The user-defined description of the Boot Order policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    aliases: [descr]
  configured_boot_mode:
    description:
      - Sets the BIOS boot mode.
      - UEFI uses the GUID Partition Table (GPT) whereas Legacy mode uses the Master Boot Record (MBR) partitioning scheme.
    choices: [Legacy, Uefi]
    default: Legacy
  uefi_enable_secure_boot:
    description:
      - Secure boot enforces that device boots using only software that is trusted by the Original Equipment Manufacturer (OEM).
      - Option is only used if configured_boot_mode is set to Uefi.
    type: bool
    default: false
  boot_devices:
    description:
      - List of Boot Devices configured on the endpoint.
    type: list
    suboptions:
      enabled:
        description:
          - Specifies if the boot device is enabled or disabled.
        type: bool
        default: true
      device_type:
        description:
          - Device type used with this boot option.
          - Choices are based on each device title in the API schema.
        choices: [iSCSI, Local CDD, Local Disk, NVMe, PCH Storage, PXE, SAN, SD Card, UEFI Shell, USB, Virtual Media]
        required: true
      device_name:
        description:
          - A name that helps identify a boot device.
          - It can be any string that adheres to the following constraints.
          - It should start and end with an alphanumeric character.
          - It can have underscores and hyphens.
          - It cannot be more than 30 characters.
        required: true
      network_slot:
        description:
          - The slot id of the controller for the iscsi and pxe device.
          - Option is used when device_type is iscsi and pxe.
        choices: [1 - 255, MLOM, L, L1, L2, OCP]
      port:
        description:
          - The port id of the controller for the iscsi and pxe device.
          - Option is used when device_type is iscsi and pxe.
          - The port id need to be an integer from 0 to 255.
      controller_slot:
        description:
          - The slot id of the controller for the local disk device.
          - Option is used when device_type is local_disk.
        choices: [1-255, M, HBA, SAS, RAID, MRAID, MSTOR-RAID]
      bootloader_name:
        description:
          - Details of the bootloader to be used during boot from local disk.
          - Option is used when device_type is local_disk and configured_boot_mode is Uefi.
      bootloader_description:
        description:
          - Details of the bootloader to be used during boot from local disk.
          - Option is used when device_type is local_disk and configured_boot_mode is Uefi.
      bootloader_path:
        description:
          - Details of the bootloader to be used during boot from local disk.
          - Option is used when device_type is local_disk and configured_boot_mode is Uefi.
      ip_type:
        description:
          - The IP Address family type to use during the PXE Boot process.
          - Option is used when device_type is pxe.
        choices: [None, IPv4, IPv6]
        default: None
      interface_source:
        description:
          - Lists the supported Interface Source for PXE device.
          - Option is used when device_type is pxe.
        choices: [name, mac, port]
        default: name
      intefrace_name:
        description:
          - The name of the underlying virtual ethernet interface used by the PXE boot device.
          - Option is used when device_type is pxe and interface_source is name.
      mac_address:
        description:
          - The MAC Address of the underlying virtual ethernet interface used by the PXE boot device.
          - Option is used when device_type is pxe and interface_source is mac.
      sd_card_subtype:
        description:
          - The subtype for the selected device type.
          - Option is used when device_type is sd_card.
        choices: [None, flex-util, flex-flash, SDCARD]
        default: None
      lun:
        description:
          - The Logical Unit Number (LUN) of the device.
          - Option is used when device_type is pch, san and sd_card.
          - The LUN need to be an integer from 0 to 255.
      usb_subtype:
        description:
          - The subtype for the selected device type.
          - Option is used when device_type is usb.
        choices: [None, usb-cd, usb-fdd, usb-hdd]
        default: None
      virtual_media_subtype:
        description:
          - The subtype for the selected device type.
          - Option is used when device_type is virtual_media.
        choices: [None, cimc-mapped-dvd, cimc-mapped-hdd, kvm-mapped-dvd, kvm-mapped-hdd, kvm-mapped-fdd]
        default: None
author:
  - Tse Kai "Kevin" Chan (@BrightScale)
version_added: '2.10'
'''

EXAMPLES = r'''
- name: Configure Boot Order Policy
  cisco.intersight.intersight_boot_order_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: DevNet
    name: COS-Boot
    description: Boot Order policy for COS
    tags:
      - Key: Site
        Value: RCDN
    configured_boot_mode: legacy
    boot_devices:
      - device_type: Local Disk
        device_name: Boot-Lun
        controller_slot: MRAID

- name: Delete Boot Order Policy
  cisco.intersight.intersight_boot_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: DevNet
    name: COS-Boot
    state: absent
'''

RETURN = r'''
api_repsonse:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "COS-Boot",
        "ObjectType": "boot.Policy",
        "Tags": [
            {
                "Key": "Site",
                "Value": "RCDN"
            }
        ]
    }
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec


def main():
    boot_device = dict(
        enabled=dict(type='bool', default=True),
        device_type=dict(
            type='str',
            choices=[
                'iSCSI',
                'Local CDD',
                'Local Disk',
                'NVMe',
                'PCH Storage',
                'PXE',
                'SAN',
                'SD Card',
                'UEFI Shell',
                'USB',
                'Virtual Media',
            ],
            required=True,
        ),
        device_name=dict(type='str', required=True),
        # iscsi and pxe options
        network_slot=dict(type='str', default=''),
        port=dict(type='int', default=0),
        # local disk options
        controller_slot=dict(type='str', default=''),
        # bootloader options
        bootloader_name=dict(type='str', default=''),
        bootloader_description=dict(type='str', default=''),
        bootloader_path=dict(type='str', default=''),
        # pxe only options
        ip_type=dict(
            type='str',
            choices=[
                'None',
                'IPv4',
                'IPv6'
            ],
            default='None'
        ),
        interface_source=dict(
            type='str',
            choices=[
                'name',
                'mac',
                'port'
            ],
            default='name'
        ),
        interface_name=dict(type='str', default=''),
        mac_address=dict(type='str', default=''),
        # sd card options
        sd_card_subtype=dict(
            type='str',
            choices=[
                'None',
                'flex-util',
                'flex-flash',
                'SDCARD'
            ],
            default='None',
        ),
        # lun for pch, san, sd_card
        lun=dict(type='int', default=0),
        # usb options
        usb_subtype=dict(
            type='str',
            choices=[
                'None',
                'usb-cd',
                'usb-fdd',
                'usb-hdd'
            ],
            default='None',
        ),
        # virtual media options
        virtual_media_subtype=dict(
            type='str',
            choices=[
                'None',
                'cimc-mapped-dvd',
                'cimc-mapped-hdd',
                'kvm-mapped-dvd',
                'kvm-mapped-hdd',
                'kvm-mapped-fdd'
            ],
            default='None',
        ),
    )
    argument_spec = intersight_argument_spec
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr'], default=''),
        tags=dict(type='list', default=[]),
        configured_boot_mode=dict(type='str', choices=['Legacy', 'Uefi'], default='Legacy'),
        uefi_enable_secure_boot=dict(type='bool', default=False),
        boot_devices=dict(type='list', elements='dict', options=boot_device),
    )

    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''
    #
    # Argument spec above, resource path, and API body should be the only code changed in each policy module
    #
    # Resource path used to configure policy
    resource_path = '/boot/PrecisionPolicies'
    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name'],
        'Tags': intersight.module.params['tags'],
        'Description': intersight.module.params['description'],
        'ConfiguredBootMode': intersight.module.params['configured_boot_mode'],
        "EnforceUefiSecureBoot": intersight.module.params['uefi_enable_secure_boot'],
        'BootDevices': [],
    }
    if intersight.module.params.get('boot_devices'):
        for device in intersight.module.params['boot_devices']:
            if device['device_type'] == 'iSCSI':
                intersight.api_body['BootDevices'].append(
                    {
                        "ClassId": "boot.Iscsi",
                        "ObjectType": "boot.Iscsi",
                        "Enabled": device['enabled'],
                        "Name": device['device_name'],
                        "Slot": device['network_slot'],
                        "Port": device['port'],
                    }
                )
            elif device['device_type'] == 'Local CDD':
                intersight.api_body['BootDevices'].append(
                    {
                        "ClassId": "boot.LocalCdd",
                        "ObjectType": "boot.LocalCdd",
                        "Enabled": device['enabled'],
                        "Name": device['device_name'],
                    }
                )
            elif device['device_type'] == 'Local Disk':
                intersight.api_body['BootDevices'].append(
                    {
                        "ClassId": "boot.LocalDisk",
                        "ObjectType": "boot.LocalDisk",
                        "Enabled": device['enabled'],
                        "Name": device['device_name'],
                        "Slot": device['controller_slot'],
                        "Bootloader": {
                            "ClassId": "boot.Bootloader",
                            "ObjectType": "boot.Bootloader",
                            "Description": device['bootloader_description'],
                            "Name": device['bootloader_name'],
                            "Path": device['bootloader_path'],
                        },
                    }
                )
            elif device['device_type'] == 'NVMe':
                intersight.api_body['BootDevices'].append(
                    {
                        "ClassId": "boot.NVMe",
                        "ObjectType": "boot.NVMe",
                        "Enabled": device['enabled'],
                        "Name": device['device_name'],
                        "Bootloader": {
                            "ClassId": "boot.Bootloader",
                            "ObjectType": "boot.Bootloader",
                            "Description": device['bootloader_description'],
                            "Name": device['bootloader_name'],
                            "Path": device['bootloader_path'],
                        },
                    }
                )
            elif device['device_type'] == 'PCH Storage':
                intersight.api_body['BootDevices'].append(
                    {
                        "ClassId": "boot.PchStorage",
                        "ObjectType": "boot.PchStorage",
                        "Enabled": device['enabled'],
                        "Name": device['device_name'],
                        "Bootloader": {
                            "ClassId": "boot.Bootloader",
                            "ObjectType": "boot.Bootloader",
                            "Description": device['bootloader_description'],
                            "Name": device['bootloader_name'],
                            "Path": device['bootloader_path'],
                        },
                        "Lun": device['lun'],
                    }
                )
            elif device['device_type'] == 'PXE':
                intersight.api_body['BootDevices'].append(
                    {
                        "ClassId": "boot.Pxe",
                        "ObjectType": "boot.Pxe",
                        "Enabled": device['enabled'],
                        "Name": device['device_name'],
                        "IpType": device['ip_type'],
                        "InterfaceSource": device['interface_source'],
                        "Slot": device['network_slot'],
                        "InterfaceName": device['interface_name'],
                        "Port": device['port'],
                        "MacAddress": device['mac_address'],
                    }
                )
            elif device['device_type'] == 'SAN':
                intersight.api_body['BootDevices'].append(
                    {
                        "ClassId": "boot.San",
                        "ObjectType": "boot.San",
                        "Enabled": device['enabled'],
                        "Name": device['device_name'],
                        "Lun": device['lun'],
                        "Slot": device['network_slot'],
                        "Bootloader": {
                            "ClassId": "boot.Bootloader",
                            "ObjectType": "boot.Bootloader",
                            "Description": device['bootloader_description'],
                            "Name": device['bootloader_name'],
                            "Path": device['bootloader_path'],
                        },
                    }
                )
            elif device['device_type'] == 'SD Card':
                intersight.api_body['BootDevices'].append(
                    {
                        "ClassId": "boot.SdCard",
                        "ObjectType": "boot.SdCard",
                        "Enabled": device['enabled'],
                        "Name": device['device_name'],
                        "Lun": device['lun'],
                        "SubType": device['sd_card_subtype'],
                        "Bootloader": {
                            "ClassId": "boot.Bootloader",
                            "ObjectType": "boot.Bootloader",
                            "Description": device['bootloader_description'],
                            "Name": device['bootloader_name'],
                            "Path": device['bootloader_path'],
                        },
                    }
                )
            elif device['device_type'] == 'UEFI Shell':
                intersight.api_body['BootDevices'].append(
                    {
                        "ClassId": "boot.UefiShell",
                        "ObjectType": "boot.UefiShell",
                        "Enabled": device['enabled'],
                        "Name": device['device_name'],
                    }
                )
            elif device['device_type'] == 'USB':
                intersight.api_body['BootDevices'].append(
                    {
                        "ClassId": "boot.Usb",
                        "ObjectType": "boot.Usb",
                        "Enabled": device['enabled'],
                        "Name": device['device_name'],
                        "SubType": device['usb_subtype'],
                    }
                )
            elif device['device_type'] == 'Virtual Media':
                intersight.api_body['BootDevices'].append(
                    {
                        "ClassId": "boot.VirtualMedia",
                        "ObjectType": "boot.VirtualMedia",
                        "Enabled": device['enabled'],
                        "Name": device['device_name'],
                        "SubType": device['virtual_media_subtype'],
                    }
                )
    #
    # Code below should be common across all policy modules
    #
    intersight.configure_policy_or_profile(resource_path=resource_path)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()

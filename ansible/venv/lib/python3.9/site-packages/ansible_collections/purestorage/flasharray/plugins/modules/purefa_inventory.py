#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2020, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: purefa_inventory
short_description: Collect information from Pure Storage FlashArray
version_added: '1.0.0'
description:
  - Collect hardware inventory information from a Pure Storage Flasharray
author:
  - Pure Storage ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
extends_documentation_fragment:
  - purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: collect FlashArray invenroty
  purestorage.flasharray.purefa_inventory:
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
- name: show inventory information
  debug:
    msg: "{{ array_info['purefa_inv'] }}"

"""

RETURN = r"""
purefa_inventory:
  description: Returns the inventory information for the FlashArray
  returned: always
  type: dict
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_system,
    get_array,
    purefa_argument_spec,
)


NEW_API_VERSION = "2.2"
SFP_API_VERSION = "2.16"


def generate_new_hardware_dict(array, versions):
    hw_info = {
        "fans": {},
        "controllers": {},
        "temps": {},
        "drives": {},
        "interfaces": {},
        "power": {},
        "chassis": {},
        "tempatures": {},
    }
    components = list(array.get_hardware().items)
    for component in range(0, len(components)):
        component_name = components[component].name
        if components[component].type == "chassis":
            hw_info["chassis"][component_name] = {
                "status": components[component].status,
                "serial": components[component].serial,
                "model": components[component].model,
                "identify_enabled": components[component].identify_enabled,
            }
        if components[component].type == "controller":
            hw_info["controllers"][component_name] = {
                "status": components[component].status,
                "serial": components[component].serial,
                "model": components[component].model,
                "identify_enabled": components[component].identify_enabled,
            }
        if components[component].type == "cooling":
            hw_info["fans"][component_name] = {
                "status": components[component].status,
            }
        if components[component].type == "temp_sensor":
            hw_info["controllers"][component_name] = {
                "status": components[component].status,
                "temperature": components[component].temperature,
            }
        if components[component].type == "drive_bay":
            hw_info["drives"][component_name] = {
                "status": components[component].status,
                "identify_enabled": components[component].identify_enabled,
                "serial": getattr(components[component], "serial", None),
            }
        if components[component].type in [
            "sas_port",
            "fc_port",
            "eth_port",
            "ib_port",
        ]:
            hw_info["interfaces"][component_name] = {
                "type": components[component].type,
                "status": components[component].status,
                "speed": components[component].speed,
                "connector_type": None,
                "rx_los": None,
                "rx_power": None,
                "static": {},
                "temperature": None,
                "tx_bias": None,
                "tx_fault": None,
                "tx_power": None,
                "voltage": None,
            }
        if components[component].type == "power_supply":
            hw_info["power"][component_name] = {
                "status": components[component].status,
                "voltage": components[component].voltage,
                "serial": components[component].serial,
                "model": components[component].model,
            }
    drives = list(array.get_drives().items)
    for drive in range(0, len(drives)):
        drive_name = drives[drive].name
        hw_info["drives"][drive_name] = {
            "capacity": drives[drive].capacity,
            "status": drives[drive].status,
            "protocol": getattr(drives[drive], "protocol", None),
            "type": drives[drive].type,
        }
    if SFP_API_VERSION in versions:
        port_details = list(array.get_network_interfaces_port_details().items)
        for port_detail in range(0, len(port_details)):
            port_name = port_details[port_detail].name
            hw_info["interfaces"][port_name]["interface_type"] = port_details[
                port_detail
            ].interface_type
            hw_info["interfaces"][port_name]["rx_los"] = (
                port_details[port_detail].rx_los[0].flag
            )
            hw_info["interfaces"][port_name]["rx_power"] = (
                port_details[port_detail].rx_power[0].measurement
            )
            hw_info["interfaces"][port_name]["static"] = {
                "connector_type": port_details[port_detail].static.connector_type,
                "vendor_name": port_details[port_detail].static.vendor_name,
                "vendor_oui": port_details[port_detail].static.vendor_oui,
                "vendor_serial_number": port_details[
                    port_detail
                ].static.vendor_serial_number,
                "vendor_part_number": port_details[
                    port_detail
                ].static.vendor_part_number,
                "vendor_date_code": port_details[port_detail].static.vendor_date_code,
                "signaling_rate": port_details[port_detail].static.signaling_rate,
                "wavelength": port_details[port_detail].static.wavelength,
                "rate_identifier": port_details[port_detail].static.rate_identifier,
                "identifier": port_details[port_detail].static.identifier,
                "link_length": port_details[port_detail].static.link_length,
                "voltage_thresholds": {
                    "alarm_high": port_details[
                        port_detail
                    ].static.voltage_thresholds.alarm_high,
                    "alarm_low": port_details[
                        port_detail
                    ].static.voltage_thresholds.alarm_low,
                    "warn_high": port_details[
                        port_detail
                    ].static.voltage_thresholds.warn_high,
                    "warn_low": port_details[
                        port_detail
                    ].static.voltage_thresholds.warn_low,
                },
                "tx_power_thresholds": {
                    "alarm_high": port_details[
                        port_detail
                    ].static.tx_power_thresholds.alarm_high,
                    "alarm_low": port_details[
                        port_detail
                    ].static.tx_power_thresholds.alarm_low,
                    "warn_high": port_details[
                        port_detail
                    ].static.tx_power_thresholds.warn_high,
                    "warn_low": port_details[
                        port_detail
                    ].static.tx_power_thresholds.warn_low,
                },
                "rx_power_thresholds": {
                    "alarm_high": port_details[
                        port_detail
                    ].static.rx_power_thresholds.alarm_high,
                    "alarm_low": port_details[
                        port_detail
                    ].static.rx_power_thresholds.alarm_low,
                    "warn_high": port_details[
                        port_detail
                    ].static.rx_power_thresholds.warn_high,
                    "warn_low": port_details[
                        port_detail
                    ].static.rx_power_thresholds.warn_low,
                },
                "tx_bias_thresholds": {
                    "alarm_high": port_details[
                        port_detail
                    ].static.tx_bias_thresholds.alarm_high,
                    "alarm_low": port_details[
                        port_detail
                    ].static.tx_bias_thresholds.alarm_low,
                    "warn_high": port_details[
                        port_detail
                    ].static.tx_bias_thresholds.warn_high,
                    "warn_low": port_details[
                        port_detail
                    ].static.tx_bias_thresholds.warn_low,
                },
                "temperature_thresholds": {
                    "alarm_high": port_details[
                        port_detail
                    ].static.temperature_thresholds.alarm_high,
                    "alarm_low": port_details[
                        port_detail
                    ].static.temperature_thresholds.alarm_low,
                    "warn_high": port_details[
                        port_detail
                    ].static.temperature_thresholds.warn_high,
                    "warn_low": port_details[
                        port_detail
                    ].static.temperature_thresholds.warn_low,
                },
                "fc_speeds": port_details[port_detail].static.fc_speeds,
                "fc_technology": port_details[port_detail].static.fc_technology,
                "encoding": port_details[port_detail].static.encoding,
                "fc_link_lengths": port_details[port_detail].static.fc_link_lengths,
                "fc_transmission_media": port_details[
                    port_detail
                ].static.fc_transmission_media,
                "extended_identifier": port_details[
                    port_detail
                ].static.extended_identifier,
            }
            hw_info["interfaces"][port_name]["temperature"] = (
                port_details[port_detail].temperature[0].measurement
            )
            hw_info["interfaces"][port_name]["tx_bias"] = (
                port_details[port_detail].tx_bias[0].measurement
            )
            hw_info["interfaces"][port_name]["tx_fault"] = (
                port_details[port_detail].tx_fault[0].flag
            )
            hw_info["interfaces"][port_name]["tx_power"] = (
                port_details[port_detail].tx_power[0].measurement
            )
            hw_info["interfaces"][port_name]["voltage"] = (
                port_details[port_detail].voltage[0].measurement
            )
    return hw_info


def generate_hardware_dict(array):
    hw_info = {
        "fans": {},
        "controllers": {},
        "temps": {},
        "drives": {},
        "interfaces": {},
        "power": {},
        "chassis": {},
    }
    components = array.list_hardware()
    for component in range(0, len(components)):
        component_name = components[component]["name"]
        if "FAN" in component_name:
            fan_name = component_name
            hw_info["fans"][fan_name] = {"status": components[component]["status"]}
        if "PWR" in component_name:
            pwr_name = component_name
            hw_info["power"][pwr_name] = {
                "status": components[component]["status"],
                "voltage": components[component]["voltage"],
                "serial": components[component]["serial"],
                "model": components[component]["model"],
            }
        if "IB" in component_name:
            ib_name = component_name
            hw_info["interfaces"][ib_name] = {
                "status": components[component]["status"],
                "speed": components[component]["speed"],
            }
        if "SAS" in component_name:
            sas_name = component_name
            hw_info["interfaces"][sas_name] = {
                "status": components[component]["status"],
                "speed": components[component]["speed"],
            }
        if "ETH" in component_name:
            eth_name = component_name
            hw_info["interfaces"][eth_name] = {
                "status": components[component]["status"],
                "speed": components[component]["speed"],
            }
        if "FC" in component_name:
            eth_name = component_name
            hw_info["interfaces"][eth_name] = {
                "status": components[component]["status"],
                "speed": components[component]["speed"],
            }
        if "TMP" in component_name:
            tmp_name = component_name
            hw_info["temps"][tmp_name] = {
                "status": components[component]["status"],
                "temperature": components[component]["temperature"],
            }
        if component_name in ["CT0", "CT1"]:
            cont_name = component_name
            hw_info["controllers"][cont_name] = {
                "status": components[component]["status"],
                "serial": components[component]["serial"],
                "model": components[component]["model"],
            }
        if component_name in ["CH0"]:
            cont_name = component_name
            hw_info["chassis"][cont_name] = {
                "status": components[component]["status"],
                "serial": components[component]["serial"],
                "model": components[component]["model"],
            }

    drives = array.list_drives()
    for drive in range(0, len(drives)):
        drive_name = drives[drive]["name"]
        hw_info["drives"][drive_name] = {
            "capacity": drives[drive]["capacity"],
            "status": drives[drive]["status"],
            "protocol": drives[drive]["protocol"],
            "type": drives[drive]["type"],
        }
        for disk in range(0, len(components)):
            if components[disk]["name"] == drive_name:
                hw_info["drives"][drive_name]["serial"] = components[disk]["serial"]

    return hw_info


def main():
    argument_spec = purefa_argument_spec()
    inv_info = {}
    module = AnsibleModule(argument_spec, supports_check_mode=True)
    array = get_system(module)
    api_version = array._list_available_rest_versions()
    if NEW_API_VERSION in api_version:
        arrayv6 = get_array(module)
        inv_info = generate_new_hardware_dict(arrayv6, api_version)
    else:
        inv_info = generate_hardware_dict(array)
    module.exit_json(changed=False, purefa_inv=inv_info)


if __name__ == "__main__":
    main()

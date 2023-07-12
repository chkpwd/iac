#!/usr/bin/python

# Copyright: (c) 2021, Dell Technologies
# Apache License version 2.0 (see MODULE-LICENSE or http://www.apache.org/licenses/LICENSE-2.0.txt)

""" Ansible module for managing SDCs on Dell Technologies (Dell) PowerFlex"""

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r'''
module: sdc
version_added: '1.0.0'
short_description: Manage SDCs on Dell PowerFlex
description:
- Managing SDCs on PowerFlex storage system includes getting details of SDC
  and renaming SDC.

author:
- Akash Shendge (@shenda1) <ansible.team@dell.com>

extends_documentation_fragment:
  - dellemc.powerflex.powerflex

options:
  sdc_name:
    description:
    - Name of the SDC.
    - Specify either I(sdc_name), I(sdc_id) or I(sdc_ip) for get/rename operation.
    - Mutually exclusive with I(sdc_id) and I(sdc_ip).
    type: str
  sdc_id:
    description:
    - ID of the SDC.
    - Specify either I(sdc_name), I(sdc_id) or I(sdc_ip) for get/rename operation.
    - Mutually exclusive with I(sdc_name) and I(sdc_ip).
    type: str
  sdc_ip:
    description:
    - IP of the SDC.
    - Specify either I(sdc_name), I(sdc_id) or I(sdc_ip) for get/rename operation.
    - Mutually exclusive with I(sdc_id) and I(sdc_name).
    type: str
  sdc_new_name:
    description:
    - New name of the SDC. Used to rename the SDC.
    type: str
  state:
    description:
    - State of the SDC.
    choices: ['present', 'absent']
    required: true
    type: str
notes:
  - The I(check_mode) is not supported.
'''

EXAMPLES = r'''
- name: Get SDC details using SDC ip
  dellemc.powerflex.sdc:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    sdc_ip: "{{sdc_ip}}"
    state: "present"

- name: Rename SDC using SDC name
  dellemc.powerflex.sdc:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    sdc_name: "centos_sdc"
    sdc_new_name: "centos_sdc_renamed"
    state: "present"
'''

RETURN = r'''
changed:
    description: Whether or not the resource has changed.
    returned: always
    type: bool
    sample: 'false'

sdc_details:
    description: Details of the SDC.
    returned: When SDC exists
    type: dict
    contains:
        id:
            description: The ID of the SDC.
            type: str
        name:
            description: Name of the SDC.
            type: str
        sdcIp:
            description: IP of the SDC.
            type: str
        osType:
            description: OS type of the SDC.
            type: str
        mapped_volumes:
            description: The details of the mapped volumes.
            type: list
            contains:
                id:
                    description: The ID of the volume.
                    type: str
                name:
                    description: The name of the volume.
                    type: str
                volumeType:
                    description: Type of the volume.
                    type: str
        sdcApproved:
            description: Indicates whether an SDC has approved access to the
                         system.
            type: bool
    sample: {
        "id": "07335d3d00000006",
        "installedSoftwareVersionInfo": "R3_6.0.0",
        "kernelBuildNumber": null,
        "kernelVersion": "3.10.0",
        "links": [
            {
                "href": "/api/instances/Sdc::07335d3d00000006",
                "rel": "self"
            },
            {
                "href": "/api/instances/Sdc::07335d3d00000006/relationships/
                        Statistics",
                "rel": "/api/Sdc/relationship/Statistics"
            },
            {
                "href": "/api/instances/Sdc::07335d3d00000006/relationships/
                        Volume",
                "rel": "/api/Sdc/relationship/Volume"
            },
            {
                "href": "/api/instances/System::4a54a8ba6df0690f",
                "rel": "/api/parent/relationship/systemId"
            }
        ],
        "mapped_volumes": [],
        "mdmConnectionState": "Disconnected",
        "memoryAllocationFailure": null,
        "name": "LGLAP203",
        "osType": "Linux",
        "peerMdmId": null,
        "perfProfile": "HighPerformance",
        "sdcApproved": true,
        "sdcApprovedIps": null,
        "sdcGuid": "F8ECB844-23B8-4629-92BB-B6E49A1744CB",
        "sdcIp": "N/A",
        "sdcIps": null,
        "sdcType": "AppSdc",
        "sdrId": null,
        "socketAllocationFailure": null,
        "softwareVersionInfo": "R3_6.0.0",
        "systemId": "4a54a8ba6df0690f",
        "versionInfo": "R3_6.0.0"
    }
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.powerflex.plugins.module_utils.storage.dell\
    import utils

LOG = utils.get_logger('sdc')


class PowerFlexSdc(object):
    """Class with SDC operations"""

    def __init__(self):
        """ Define all parameters required by this module"""
        self.module_params = utils.get_powerflex_gateway_host_parameters()
        self.module_params.update(get_powerflex_sdc_parameters())

        mutually_exclusive = [['sdc_id', 'sdc_ip', 'sdc_name']]

        required_one_of = [['sdc_id', 'sdc_ip', 'sdc_name']]

        # initialize the Ansible module
        self.module = AnsibleModule(
            argument_spec=self.module_params,
            supports_check_mode=False,
            mutually_exclusive=mutually_exclusive,
            required_one_of=required_one_of)

        utils.ensure_required_libs(self.module)

        try:
            self.powerflex_conn = utils.get_powerflex_gateway_host_connection(
                self.module.params)
            LOG.info("Got the PowerFlex system connection object instance")
        except Exception as e:
            LOG.error(str(e))
            self.module.fail_json(msg=str(e))

    def rename_sdc(self, sdc_id, new_name):
        """Rename SDC
        :param sdc_id: The ID of the SDC
        :param new_name: The new name of the SDC
        :return: Boolean indicating if rename operation is successful
        """

        try:
            self.powerflex_conn.sdc.rename(sdc_id=sdc_id, name=new_name)
            return True
        except Exception as e:
            errormsg = "Failed to rename SDC %s with error %s" % (sdc_id,
                                                                  str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def get_mapped_volumes(self, sdc_id):
        """Get volumes mapped to SDC
        :param sdc_id: The ID of the SDC
        :return: List containing volume details mapped to SDC
        """

        try:
            resp = self.powerflex_conn.sdc.get_mapped_volumes(sdc_id=sdc_id)
            return resp
        except Exception as e:
            errormsg = "Failed to get the volumes mapped to SDC %s with " \
                       "error %s" % (sdc_id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def get_sdc(self, sdc_name=None, sdc_ip=None, sdc_id=None):
        """Get the SDC Details
            :param sdc_name: The name of the SDC
            :param sdc_ip: The IP of the SDC
            :param sdc_id: The ID of the SDC
            :return: The dict containing SDC details
        """

        if sdc_name:
            id_ip_name = sdc_name
        elif sdc_ip:
            id_ip_name = sdc_ip
        else:
            id_ip_name = sdc_id

        try:
            if sdc_name:
                sdc_details = self.powerflex_conn.sdc.get(
                    filter_fields={'name': sdc_name})
            elif sdc_ip:
                sdc_details = self.powerflex_conn.sdc.get(
                    filter_fields={'sdcIp': sdc_ip})
            else:
                sdc_details = self.powerflex_conn.sdc.get(
                    filter_fields={'id': sdc_id})

            if len(sdc_details) == 0:
                error_msg = "Unable to find SDC with identifier %s" \
                            % id_ip_name
                LOG.error(error_msg)
                return None
            sdc_details[0]['mapped_volumes'] = self.get_mapped_volumes(
                sdc_details[0]['id'])
            return sdc_details[0]
        except Exception as e:
            errormsg = "Failed to get the SDC %s with error %s" % (
                id_ip_name, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def validate_parameters(self, sdc_name=None, sdc_id=None, sdc_ip=None):
        """Validate the input parameters"""

        if all(param is None for param in [sdc_name, sdc_id, sdc_ip]):
            self.module.fail_json(msg="Please provide sdc_name/sdc_id/sdc_ip "
                                  "with valid input.")

        sdc_identifiers = ['sdc_name', 'sdc_id', 'sdc_ip']
        for param in sdc_identifiers:
            if self.module.params[param] is not None and \
                    len(self.module.params[param].strip()) == 0:
                error_msg = "Please provide valid %s" % param
                self.module.fail_json(msg=error_msg)

    def perform_module_operation(self):
        """
        Perform different actions on SDC based on parameters passed in
        the playbook
        """
        sdc_name = self.module.params['sdc_name']
        sdc_id = self.module.params['sdc_id']
        sdc_ip = self.module.params['sdc_ip']
        sdc_new_name = self.module.params['sdc_new_name']
        state = self.module.params['state']

        # result is a dictionary to contain end state and SDC details
        changed = False
        result = dict(
            changed=False,
            sdc_details={}
        )

        self.validate_parameters(sdc_name, sdc_id, sdc_ip)

        sdc_details = self.get_sdc(sdc_name=sdc_name, sdc_id=sdc_id,
                                   sdc_ip=sdc_ip)
        if sdc_name:
            id_ip_name = sdc_name
        elif sdc_ip:
            id_ip_name = sdc_ip
        else:
            id_ip_name = sdc_id

        if state == 'present' and not sdc_details:
            error_msg = 'Could not find any SDC instance with ' \
                        'identifier %s.' % id_ip_name
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

        if state == 'absent' and sdc_details:
            error_msg = 'Removal of SDC is not allowed through Ansible ' \
                        'module.'
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

        if state == 'present' and sdc_details and sdc_new_name is not None:
            if len(sdc_new_name.strip()) == 0:
                self.module.fail_json(msg="Please provide valid SDC name.")

            changed = self.rename_sdc(sdc_details['id'], sdc_new_name)

            if changed:
                sdc_name = sdc_new_name

        if state == 'present':
            result['sdc_details'] = self.get_sdc(sdc_name=sdc_name,
                                                 sdc_id=sdc_id, sdc_ip=sdc_ip)
        result['changed'] = changed
        self.module.exit_json(**result)


def get_powerflex_sdc_parameters():
    """This method provide parameter required for the Ansible SDC module on
    PowerFlex"""
    return dict(
        sdc_id=dict(),
        sdc_ip=dict(),
        sdc_name=dict(),
        sdc_new_name=dict(),
        state=dict(required=True, type='str', choices=['present', 'absent'])
    )


def main():
    """ Create PowerFlex SDC object and perform actions on it
        based on user input from playbook"""
    obj = PowerFlexSdc()
    obj.perform_module_operation()


if __name__ == '__main__':
    main()

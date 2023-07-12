#!/usr/bin/python

# Copyright: (c) 2021, Dell Technologies
# Apache License version 2.0 (see MODULE-LICENSE or http://www.apache.org/licenses/LICENSE-2.0.txt)

""" Ansible module for managing SDS on Dell Technologies (Dell) PowerFlex"""

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r'''
module: sds
version_added: '1.1.0'
short_description: Manage SDS on Dell PowerFlex
description:
- Managing SDS on PowerFlex storage system includes
  creating new SDS, getting details of SDS, adding/removing IP to/from SDS,
  modifying attributes of SDS, and deleting SDS.
author:
- Rajshree Khare (@khareRajshree) <ansible.team@dell.com>
extends_documentation_fragment:
  - dellemc.powerflex.powerflex
options:
  sds_name:
    description:
    - The name of the SDS.
    - Mandatory for create operation.
    - It is unique across the PowerFlex array.
    - Mutually exclusive with I(sds_id).
    type: str
  sds_id:
    description:
    - The ID of the SDS.
    - Except create operation, all other operations can be performed
      using I(sds_id).
    - Mutually exclusive with I(sds_name).
    type: str
  protection_domain_name:
    description:
    - The name of the protection domain.
    - Mutually exclusive with I(protection_domain_id).
    type: str
  protection_domain_id:
    description:
    - The ID of the protection domain.
    - Mutually exclusive with I(protection_domain_name).
    type: str
  sds_ip_list:
    description:
    - Dictionary of IPs and their roles for the SDS.
    - At least one IP-role is mandatory while creating a SDS.
    - IP-roles can be updated as well.
    type: list
    elements: dict
    suboptions:
      ip:
        description:
        - IP address of the SDS.
        type: str
        required: true
      role:
        description:
        - Role assigned to the SDS IP address.
        choices: ['sdsOnly', 'sdcOnly', 'all']
        type: str
        required: true
  sds_ip_state:
    description:
    - State of IP with respect to the SDS.
    choices: ['present-in-sds', 'absent-in-sds']
    type: str
  rfcache_enabled:
    description:
    - Whether to enable the Read Flash cache.
    type: bool
  rmcache_enabled:
    description:
    - Whether to enable the Read RAM cache.
    type: bool
  rmcache_size:
    description:
    - Read RAM cache size (in MB).
    - Minimum size is 128 MB.
    - Maximum size is 3911 MB.
    type: int
  sds_new_name:
    description:
    - SDS new name.
    type: str
  performance_profile:
    description:
    - Performance profile to apply to the SDS.
    - The HighPerformance profile configures a predefined set of parameters
      for very high performance use cases.
    - Default value by API is C(HighPerformance).
    choices: ['Compact', 'HighPerformance']
    type: str
  state:
    description:
    - State of the SDS.
    choices: ['present', 'absent']
    required: true
    type: str
notes:
  - The maximum limit for the IPs that can be associated with an SDS is 8.
  - There needs to be at least 1 IP for SDS communication and 1 for SDC
    communication.
  - If only 1 IP exists, it must be with role 'all'; else 1 IP
    can be with role 'all'and other IPs with role 'sdcOnly'; or 1 IP must be
    with role 'sdsOnly' and others with role 'sdcOnly'.
  - There can be 1 or more IPs with role 'sdcOnly'.
  - There must be only 1 IP with SDS role (either with role 'all' or
    'sdsOnly').
  - SDS can be created with RF cache disabled, but, be aware that the RF cache
    is not always updated. In this case, the user should re-try the operation.
  - The I(check_mode) is not supported.
'''

EXAMPLES = r'''
- name: Create SDS
  dellemc.powerflex.sds:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    sds_name: "node0"
    protection_domain_name: "domain1"
    sds_ip_list:
      - ip: "198.10.xxx.xxx"
        role: "all"
    sds_ip_state: "present-in-sds"
    state: "present"

- name: Create SDS with all parameters
  dellemc.powerflex.sds:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    sds_name: "node1"
    protection_domain_name: "domain1"
    sds_ip_list:
      - ip: "198.10.xxx.xxx"
        role: "sdcOnly"
    sds_ip_state: "present-in-sds"
    rmcache_enabled: true
    rmcache_size: 128
    performance_profile: "HighPerformance"
    state: "present"

- name: Get SDS details using name
  dellemc.powerflex.sds:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    sds_name: "node0"
    state: "present"

- name: Get SDS details using ID
  dellemc.powerflex.sds:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    sds_id: "5718253c00000004"
    state: "present"

- name: Modify SDS attributes using name
  dellemc.powerflex.sds:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    sds_name: "node0"
    sds_new_name: "node0_new"
    rfcache_enabled: true
    rmcache_enabled: true
    rmcache_size: 256
    performance_profile: "HighPerformance"
    state: "present"

- name: Modify SDS attributes using ID
  dellemc.powerflex.sds:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    sds_id: "5718253c00000004"
    sds_new_name: "node0_new"
    rfcache_enabled: true
    rmcache_enabled: true
    rmcache_size: 256
    performance_profile: "HighPerformance"
    state: "present"

- name: Add IP and role to an SDS
  dellemc.powerflex.sds:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    sds_name: "node0"
    sds_ip_list:
      - ip: "198.10.xxx.xxx"
        role: "sdcOnly"
    sds_ip_state: "present-in-sds"
    state: "present"

- name: Remove IP and role from an SDS
  dellemc.powerflex.sds:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    sds_name: "node0"
    sds_ip_list:
      - ip: "198.10.xxx.xxx"
        role: "sdcOnly"
    sds_ip_state: "absent-in-sds"
    state: "present"

- name: Delete SDS using name
  dellemc.powerflex.sds:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    sds_name: "node0"
    state: "absent"

- name: Delete SDS using ID
  dellemc.powerflex.sds:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    sds_id: "5718253c00000004"
    state: "absent"
'''

RETURN = r'''
changed:
    description: Whether or not the resource has changed.
    returned: always
    type: bool
    sample: 'false'
sds_details:
    description: Details of the SDS.
    returned: When SDS exists
    type: dict
    contains:
        authenticationError:
            description: Indicates authentication error.
            type: str
        certificateInfo:
            description: Information about certificate.
            type: str
        configuredDrlMode:
            description: Configured DRL mode.
            type: str
        drlMode:
            description: DRL mode.
            type: str
        faultSetId:
            description: Fault set ID.
            type: str
        fglMetadataCacheSize:
            description: FGL metadata cache size.
            type: int
        fglMetadataCacheState:
            description: FGL metadata cache state.
            type: str
        fglNumConcurrentWrites:
            description: FGL concurrent writes.
            type: int
        id:
            description: SDS ID.
            type: str
        ipList:
            description: SDS IP list.
            type: list
            contains:
                ip:
                    description: IP present in the SDS.
                    type: str
                role:
                    description: Role of the SDS IP.
                    type: str
        lastUpgradeTime:
            description: Last time SDS was upgraded.
            type: str
        links:
            description: SDS links.
            type: list
            contains:
                href:
                    description: SDS instance URL.
                    type: str
                rel:
                    description: SDS's relationship with different entities.
                    type: str
        maintenanceState:
            description: Maintenance state.
            type: str
        maintenanceType:
            description: Maintenance type.
            type: str
        mdmConnectionState:
            description: MDM connection state.
            type: str
        membershipState:
            description: Membership state.
            type: str
        name:
            description: Name of the SDS.
            type: str
        numOfIoBuffers:
            description: Number of IO buffers.
            type: int
        numRestarts:
            description: Number of restarts.
            type: int
        onVmWare:
            description: Presence on VMware.
            type: bool
        perfProfile:
            description: Performance profile.
            type: str
        port:
            description: SDS port.
            type: int
        protectionDomainId:
            description: Protection Domain ID.
            type: str
        protectionDomainName:
            description: Protection Domain Name.
            type: str
        raidControllers:
            description: Number of RAID controllers.
            type: int
        rfcacheEnabled:
            description: Whether RF cache is enabled or not.
            type: bool
        rfcacheErrorApiVersionMismatch:
            description: RF cache error for API version mismatch.
            type: bool
        rfcacheErrorDeviceDoesNotExist:
            description: RF cache error for device does not exist.
            type: bool
        rfcacheErrorInconsistentCacheConfiguration:
            description: RF cache error for inconsistent cache configuration.
            type: bool
        rfcacheErrorInconsistentSourceConfiguration:
            description: RF cache error for inconsistent source configuration.
            type: bool
        rfcacheErrorInvalidDriverPath:
            description: RF cache error for invalid driver path.
            type: bool
        rfcacheErrorLowResources:
            description: RF cache error for low resources.
            type: bool
        rmcacheEnabled:
            description: Whether Read RAM cache is enabled or not.
            type: bool
        rmcacheFrozen:
            description: RM cache frozen.
            type: bool
        rmcacheMemoryAllocationState:
            description: RM cache memory allocation state.
            type: bool
        rmcacheSizeInKb:
            description: RM cache size in KB.
            type: int
        rmcacheSizeInMb:
            description: RM cache size in MB.
            type: int
        sdsConfigurationFailure:
            description: SDS configuration failure.
            type: str
        sdsDecoupled:
            description: SDS decoupled.
            type: str
        sdsReceiveBufferAllocationFailures:
            description: SDS receive buffer allocation failures.
            type: str
        sdsState:
            description: SDS state.
            type: str
        softwareVersionInfo:
            description: SDS software version information.
            type: str
    sample: {
        "authenticationError": "None",
        "certificateInfo": null,
        "configuredDrlMode": "Volatile",
        "drlMode": "Volatile",
        "faultSetId": null,
        "fglMetadataCacheSize": 0,
        "fglMetadataCacheState": "Disabled",
        "fglNumConcurrentWrites": 1000,
        "id": "8f3bb0cc00000002",
        "ipList": [
            {
                "ip": "10.47.xxx.xxx",
                "role": "all"
            }
        ],
        "lastUpgradeTime": 0,
        "links": [
            {
                "href": "/api/instances/Sds::8f3bb0cc00000002",
                "rel": "self"
            },
            {
                "href": "/api/instances/Sds::8f3bb0cc00000002/relationships
                        /Statistics",
                "rel": "/api/Sds/relationship/Statistics"
            },
            {
                "href": "/api/instances/Sds::8f3bb0cc00000002/relationships
                        /SpSds",
                "rel": "/api/Sds/relationship/SpSds"
            },
            {
                "href": "/api/instances/Sds::8f3bb0cc00000002/relationships
                        /Device",
                "rel": "/api/Sds/relationship/Device"
            },
            {
                "href": "/api/instances/ProtectionDomain::9300c1f900000000",
                "rel": "/api/parent/relationship/protectionDomainId"
            }
        ],
        "maintenanceState": "NoMaintenance",
        "maintenanceType": "NoMaintenance",
        "mdmConnectionState": "Connected",
        "membershipState": "Joined",
        "name": "node0",
        "numOfIoBuffers": null,
        "numRestarts": 2,
        "onVmWare": true,
        "perfProfile": "HighPerformance",
        "port": 7072,
        "protectionDomainId": "9300c1f900000000",
        "protectionDomainName": "domain1",
        "raidControllers": null,
        "rfcacheEnabled": true,
        "rfcacheErrorApiVersionMismatch": false,
        "rfcacheErrorDeviceDoesNotExist": false,
        "rfcacheErrorInconsistentCacheConfiguration": false,
        "rfcacheErrorInconsistentSourceConfiguration": false,
        "rfcacheErrorInvalidDriverPath": false,
        "rfcacheErrorLowResources": false,
        "rmcacheEnabled": true,
        "rmcacheFrozen": false,
        "rmcacheMemoryAllocationState": "AllocationPending",
        "rmcacheSizeInKb": 131072,
        "rmcacheSizeInMb": 128,
        "sdsConfigurationFailure": null,
        "sdsDecoupled": null,
        "sdsReceiveBufferAllocationFailures": null,
        "sdsState": "Normal",
        "softwareVersionInfo": "R3_6.0.0"
    }
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.powerflex.plugins.module_utils.storage.dell\
    import utils
import copy

LOG = utils.get_logger('sds')


class PowerFlexSDS(object):
    """Class with SDS operations"""

    def __init__(self):
        """ Define all parameters required by this module"""
        self.module_params = utils.get_powerflex_gateway_host_parameters()
        self.module_params.update(get_powerflex_sds_parameters())

        mut_ex_args = [['sds_name', 'sds_id'],
                       ['protection_domain_name', 'protection_domain_id']]

        required_together_args = [['sds_ip_list', 'sds_ip_state']]

        required_one_of_args = [['sds_name', 'sds_id']]

        # initialize the Ansible module
        self.module = AnsibleModule(
            argument_spec=self.module_params,
            supports_check_mode=False,
            mutually_exclusive=mut_ex_args,
            required_together=required_together_args,
            required_one_of=required_one_of_args)

        utils.ensure_required_libs(self.module)

        try:
            self.powerflex_conn = utils.get_powerflex_gateway_host_connection(
                self.module.params)
            LOG.info("Got the PowerFlex system connection object instance")
        except Exception as e:
            LOG.error(str(e))
            self.module.fail_json(msg=str(e))

    def validate_rmcache_size_parameter(self, rmcache_enabled, rmcache_size):
        """Validate the input parameters"""

        # RM cache size cannot be set only when RM cache is enabled
        if rmcache_size is not None and rmcache_enabled is False:
            error_msg = "RM cache size can be set only when RM cache " \
                        "is enabled, please enable it along with RM " \
                        "cache size."
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def validate_ip_parameter(self, sds_ip_list):
        """Validate the input parameters"""

        if sds_ip_list is None or len(sds_ip_list) == 0:
            error_msg = "Provide valid values for " \
                        "sds_ip_list as 'ip' and 'role' for Create/Modify " \
                        "operations."
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def get_sds_details(self, sds_name=None, sds_id=None):
        """Get SDS details
            :param sds_name: Name of the SDS
            :type sds_name: str
            :param sds_id: ID of the SDS
            :type sds_id: str
            :return: Details of SDS if it exist
            :rtype: dict
        """

        id_or_name = sds_id if sds_id else sds_name

        try:
            if sds_name:
                sds_details = self.powerflex_conn.sds.get(
                    filter_fields={'name': sds_name})
            else:
                sds_details = self.powerflex_conn.sds.get(
                    filter_fields={'id': sds_id})

            if len(sds_details) == 0:
                msg = "SDS with identifier '%s' not found" % id_or_name
                LOG.info(msg)
                return None

            return sds_details[0]

        except Exception as e:
            error_msg = "Failed to get the SDS '%s' with error '%s'" \
                        % (id_or_name, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def get_protection_domain(self, protection_domain_name=None,
                              protection_domain_id=None):
        """Get protection domain details
            :param protection_domain_name: Name of the protection domain
            :param protection_domain_id: ID of the protection domain
            :return: Protection domain details
            :rtype: dict
        """
        name_or_id = protection_domain_id if protection_domain_id \
            else protection_domain_name
        try:
            pd_details = None
            if protection_domain_id:
                pd_details = self.powerflex_conn.protection_domain.get(
                    filter_fields={'id': protection_domain_id})

            if protection_domain_name:
                pd_details = self.powerflex_conn.protection_domain.get(
                    filter_fields={'name': protection_domain_name})

            if not pd_details:
                error_msg = "Unable to find the protection domain with " \
                            "'%s'. Please enter a valid protection domain " \
                            "name/id." % name_or_id
                LOG.error(error_msg)
                self.module.fail_json(msg=error_msg)

            return pd_details[0]

        except Exception as e:
            error_msg = "Failed to get the protection domain '%s' with " \
                        "error '%s'" % (name_or_id, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def restructure_ip_role_dict(self, sds_ip_list):
        """Restructure IP role dict
            :param sds_ip_list: List of one or more IP addresses and
                                their roles
            :type sds_ip_list: list[dict]
            :return: List of one or more IP addresses and their roles
            :rtype: list[dict]
        """
        new_sds_ip_list = []
        for item in sds_ip_list:
            new_sds_ip_list.append({"SdsIp": item})
        return new_sds_ip_list

    def create_sds(self, protection_domain_id, sds_ip_list, sds_ip_state,
                   sds_name, rmcache_enabled=None, rmcache_size=None):
        """Create SDS
            :param protection_domain_id: ID of the Protection Domain
            :type protection_domain_id: str
            :param sds_ip_list: List of one or more IP addresses associated
                                with the SDS over which the data will be
                                transferred.
            :type sds_ip_list: list[dict]
            :param sds_ip_state: SDS IP state
            :type sds_ip_state: str
            :param sds_name: SDS name
            :type sds_name: str
            :param rmcache_enabled: Whether to enable the Read RAM cache
            :type rmcache_enabled: bool
            :param rmcache_size: Read RAM cache size (in MB)
            :type rmcache_size: int
            :return: Boolean indicating if create operation is successful
        """
        try:
            if sds_name is None or len(sds_name.strip()) == 0:
                error_msg = "Please provide valid sds_name value for " \
                            "creation of SDS."
                LOG.error(error_msg)
                self.module.fail_json(msg=error_msg)

            if protection_domain_id is None:
                error_msg = "Protection Domain is a mandatory parameter " \
                            "for creating a SDS. Please enter a valid value."
                LOG.error(error_msg)
                self.module.fail_json(msg=error_msg)

            if sds_ip_list is None or len(sds_ip_list) == 0:
                error_msg = "Please provide valid sds_ip_list values for " \
                            "creation of SDS."
                LOG.error(error_msg)
                self.module.fail_json(msg=error_msg)

            if sds_ip_state is not None and sds_ip_state != "present-in-sds":
                error_msg = "Incorrect IP state given for creation of SDS."
                LOG.error(error_msg)
                self.module.fail_json(msg=error_msg)

            # Restructure IP-role parameter format
            if sds_ip_list and sds_ip_state == "present-in-sds":
                sds_ip_list = self.restructure_ip_role_dict(sds_ip_list)

            if rmcache_size is not None:
                self.validate_rmcache_size_parameter(rmcache_enabled,
                                                     rmcache_size)
                # set rmcache size in KB
                rmcache_size = rmcache_size * 1024

            create_params = ("protection_domain_id: %s,"
                             " sds_ip_list: %s,"
                             " sds_name: %s,"
                             " rmcache_enabled: %s, "
                             " rmcache_size_KB: %s"
                             % (protection_domain_id, sds_ip_list,
                                sds_name, rmcache_enabled, rmcache_size))
            LOG.info("Creating SDS with params: %s", create_params)

            self.powerflex_conn.sds.create(
                protection_domain_id=protection_domain_id,
                sds_ips=sds_ip_list,
                name=sds_name,
                rmcache_enabled=rmcache_enabled,
                rmcache_size_in_kb=rmcache_size)
            return True

        except Exception as e:
            error_msg = "Create SDS '%s' operation failed with error '%s'" \
                        % (sds_name, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def to_modify(self, sds_details, sds_new_name, rfcache_enabled,
                  rmcache_enabled, rmcache_size, performance_profile):
        """
        :param sds_details: Details of the SDS
        :type sds_details: dict
        :param sds_new_name: New name of SDS
        :type sds_new_name: str
        :param rfcache_enabled: Whether to enable the Read Flash cache
        :type rfcache_enabled: bool
        :param rmcache_enabled: Whether to enable the Read RAM cache
        :type rmcache_enabled: bool
        :param rmcache_size: Read RAM cache size (in MB)
        :type rmcache_size: int
        :param performance_profile: Performance profile to apply to the SDS
        :type performance_profile: str
        :return: Dictionary containing the attributes of SDS which are to be
                 updated
        :rtype: dict
        """
        modify_dict = {}

        if sds_new_name is not None:
            if len(sds_new_name.strip()) == 0:
                error_msg = "Please provide valid SDS name."
                LOG.error(error_msg)
                self.module.fail_json(msg=error_msg)
            if sds_new_name != sds_details['name']:
                modify_dict['name'] = sds_new_name

        if rfcache_enabled is not None and \
                sds_details['rfcacheEnabled'] != rfcache_enabled:
            modify_dict['rfcacheEnabled'] = rfcache_enabled

        if rmcache_enabled is not None and \
                sds_details['rmcacheEnabled'] != rmcache_enabled:
            modify_dict['rmcacheEnabled'] = rmcache_enabled

        if rmcache_size is not None:
            self.validate_rmcache_size_parameter(rmcache_enabled,
                                                 rmcache_size)
            exisitng_size_mb = sds_details['rmcacheSizeInKb'] / 1024
            if rmcache_size != exisitng_size_mb:
                if sds_details['rmcacheEnabled']:
                    modify_dict['rmcacheSizeInMB'] = rmcache_size
                else:
                    error_msg = "Failed to update RM cache size for the " \
                                "SDS '%s' as RM cache is disabled " \
                                "previously, please enable it before " \
                                "setting the size." \
                                % sds_details['name']
                    LOG.error(error_msg)
                    self.module.fail_json(msg=error_msg)

        if performance_profile is not None and \
                sds_details['perfProfile'] != performance_profile:
            modify_dict['perfProfile'] = performance_profile

        return modify_dict

    def modify_sds_attributes(self, sds_id, modify_dict,
                              create_flag=False):
        """Modify SDS attributes
            :param sds_id: SDS ID
            :type sds_id: str
            :param modify_dict: Dictionary containing the attributes of SDS
                                which are to be updated
            :type modify_dict: dict
            :param create_flag: Flag to indicate whether modify operation is
                                followed by create operation or not
            :type create_flag: bool
            :return: Boolean indicating if the operation is successful
        """
        try:
            msg = "Dictionary containing attributes which are to be" \
                  " updated is '%s'." % (str(modify_dict))
            LOG.info(msg)

            if 'name' in modify_dict:
                self.powerflex_conn.sds.rename(sds_id, modify_dict['name'])
                msg = "The name of the SDS is updated to '%s' successfully." \
                      % modify_dict['name']
                LOG.info(msg)

            if 'rfcacheEnabled' in modify_dict:
                self.powerflex_conn.sds.set_rfcache_enabled(
                    sds_id, modify_dict['rfcacheEnabled'])
                msg = "The use RFcache is updated to '%s' successfully." \
                      % modify_dict['rfcacheEnabled']
                LOG.info(msg)

            if 'rmcacheEnabled' in modify_dict:
                self.powerflex_conn.sds.set_rmcache_enabled(
                    sds_id, modify_dict['rmcacheEnabled'])
                msg = "The use RMcache is updated to '%s' successfully." \
                      % modify_dict['rmcacheEnabled']
                LOG.info(msg)

            if 'rmcacheSizeInMB' in modify_dict:
                self.powerflex_conn.sds.set_rmcache_size(
                    sds_id, modify_dict['rmcacheSizeInMB'])
                msg = "The size of RMcache is updated to '%s' successfully." \
                      % modify_dict['rmcacheSizeInMB']
                LOG.info(msg)

            if 'perfProfile' in modify_dict:
                self.powerflex_conn.sds.set_performance_parameters(
                    sds_id, modify_dict['perfProfile'])
                msg = "The performance profile is updated to '%s'" \
                      % modify_dict['perfProfile']
                LOG.info(msg)

            return True
        except Exception as e:
            if create_flag:
                error_msg = "Create SDS is successful, but failed to update" \
                            " the SDS '%s' with error '%s'"\
                            % (sds_id, str(e))
            else:
                error_msg = "Failed to update the SDS '%s' with error '%s'" \
                            % (sds_id, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def identify_ip_role(self, sds_ip_list, sds_details, sds_ip_state):
        """Identify IPs before addition/removal
            :param sds_ip_list: List of one or more IP addresses and
                                their roles
            :type sds_ip_list: list[dict]
            :param sds_details: SDS details
            :type sds_details: dict
            :param sds_ip_state: State of IP in SDS
            :type sds_ip_state: str
            :return: List containing the key-value pairs of IP-role for an
                     SDS
            :rtype: list[dict]
        """
        existing_ip_role_list = sds_details['ipList']

        # identify IPs to add or roles to update
        if sds_ip_state == "present-in-sds":
            update_role = []
            ips_to_add = []

            # identify IPs to add
            existing_ip_list = []
            if existing_ip_role_list:
                for ip in existing_ip_role_list:
                    existing_ip_list.append(ip['ip'])
            for given_ip in sds_ip_list:
                ip = given_ip['ip']
                if ip not in existing_ip_list:
                    ips_to_add.append(given_ip)
            LOG.info("IP(s) to be added: %s", ips_to_add)

            if len(ips_to_add) != 0:
                for ip in ips_to_add:
                    sds_ip_list.remove(ip)

            # identify IPs whose role needs to be updated
            update_role = [ip for ip in sds_ip_list
                           if ip not in existing_ip_role_list]
            LOG.info("Role update needed for: %s", update_role)

            return ips_to_add, update_role

        elif sds_ip_state == "absent-in-sds":
            # identify IPs to remove
            ips_to_remove = [ip for ip in existing_ip_role_list
                             if ip in sds_ip_list]
            if len(ips_to_remove) != 0:
                LOG.info("IP(s) to remove: %s", ips_to_remove)
                return ips_to_remove
            else:
                LOG.info("IP(s) do not exists.")
                return False, None

    def add_ip(self, sds_id, sds_ip_list):
        """Add IP to SDS
            :param sds_id: SDS ID
            :type sds_id: str
            :param sds_ip_list: List of one or more IP addresses and
                                their roles
            :type sds_ip_list: list[dict]
            :return: Boolean indicating if add IP operation is successful
        """
        try:
            for ip in sds_ip_list:
                LOG.info("IP to add: %s", ip)
                self.powerflex_conn.sds.add_ip(sds_id=sds_id, sds_ip=ip)
                LOG.info("IP added successfully.")
            return True
        except Exception as e:
            error_msg = "Add IP to SDS '%s' operation failed with " \
                        "error '%s'" % (sds_id, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def update_role(self, sds_id, sds_ip_list):
        """Update IP's role for an SDS
            :param sds_id: SDS ID
            :type sds_id: str
            :param sds_ip_list: List of one or more IP addresses and
                                their roles
            :type sds_ip_list: list[dict]
            :return: Boolean indicating if add IP operation is successful
        """
        try:
            LOG.info("Role updates for: %s", sds_ip_list)
            if len(sds_ip_list) != 0:
                for ip in sds_ip_list:
                    LOG.info("ip-role: %s", ip)
                    self.powerflex_conn.sds.set_ip_role(sds_id, ip['ip'],
                                                        ip['role'])
                    msg = "The role '%s' for IP '%s' is updated " \
                          "successfully." % (ip['role'], ip['ip'])
                    LOG.info(msg)
            return True
        except Exception as e:
            error_msg = "Update role of IP for SDS '%s' operation failed " \
                        "with error '%s'" % (sds_id, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def remove_ip(self, sds_id, sds_ip_list):
        """Remove IP from SDS
            :param sds_id: SDS ID
            :type sds_id: str
            :param sds_ip_list: List of one or more IP addresses and
                                their roles.
            :type sds_ip_list: list[dict]
            :return: Boolean indicating if remove IP operation is successful
        """
        try:
            for ip in sds_ip_list:
                LOG.info("IP to remove: %s", ip)
                self.powerflex_conn.sds.remove_ip(sds_id=sds_id, ip=ip['ip'])
                LOG.info("IP removed successfully.")
            return True
        except Exception as e:
            error_msg = "Remove IP from SDS '%s' operation failed with " \
                        "error '%s'" % (sds_id, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def delete_sds(self, sds_id):
        """Delete SDS
            :param sds_id: SDS ID
            :type sds_id: str
            :return: Boolean indicating if delete operation is successful
        """
        try:
            self.powerflex_conn.sds.delete(sds_id)
            return True
        except Exception as e:
            error_msg = "Delete SDS '%s' operation failed with error '%s'" \
                        % (sds_id, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def perform_module_operation(self):
        """
        Perform different actions on SDS based on parameters passed in
        the playbook
        """
        sds_name = self.module.params['sds_name']
        sds_id = self.module.params['sds_id']
        sds_new_name = self.module.params['sds_new_name']
        protection_domain_name = self.module.params['protection_domain_name']
        protection_domain_id = self.module.params['protection_domain_id']
        rfcache_enabled = self.module.params['rfcache_enabled']
        rmcache_enabled = self.module.params['rmcache_enabled']
        rmcache_size = self.module.params['rmcache_size']
        sds_ip_list = copy.deepcopy(self.module.params['sds_ip_list'])
        sds_ip_state = self.module.params['sds_ip_state']
        performance_profile = self.module.params['performance_profile']
        state = self.module.params['state']

        # result is a dictionary to contain end state and SDS details
        changed = False
        result = dict(
            changed=False,
            sds_details={}
        )

        # get SDS details
        sds_details = self.get_sds_details(sds_name, sds_id)
        if sds_details:
            sds_id = sds_details['id']
        msg = "Fetched the SDS details %s" % (str(sds_details))
        LOG.info(msg)

        # get Protection Domain ID from name
        if protection_domain_name:
            pd_details = self.get_protection_domain(protection_domain_name)
            if pd_details:
                protection_domain_id = pd_details['id']
            msg = "Fetched the protection domain details with id '%s', " \
                  "name '%s'" % (protection_domain_id, protection_domain_name)
            LOG.info(msg)

        # create operation
        create_changed = False
        if state == 'present' and not sds_details:
            if sds_id:
                error_msg = "Creation of SDS is allowed using sds_name " \
                            "only, sds_id given."
                LOG.info(error_msg)
                self.module.fail_json(msg=error_msg)

            if sds_new_name:
                error_msg = "sds_new_name parameter is not supported " \
                            "during creation of a SDS. Try renaming the " \
                            "SDS after the creation."
                LOG.info(error_msg)
                self.module.fail_json(msg=error_msg)

            self.validate_ip_parameter(sds_ip_list)

            create_changed = self.create_sds(protection_domain_id,
                                             sds_ip_list, sds_ip_state,
                                             sds_name, rmcache_enabled,
                                             rmcache_size)
            if create_changed:
                sds_details = self.get_sds_details(sds_name)
                sds_id = sds_details['id']
                msg = "SDS created successfully, fetched SDS details %s"\
                      % (str(sds_details))
                LOG.info(msg)

        # checking if basic SDS parameters are modified or not
        modify_dict = {}
        if sds_details and state == 'present':
            modify_dict = self.to_modify(sds_details, sds_new_name,
                                         rfcache_enabled, rmcache_enabled,
                                         rmcache_size, performance_profile)
            msg = "Parameters to be modified are as follows: %s"\
                  % (str(modify_dict))
            LOG.info(msg)

        # modify operation
        modify_changed = False
        if modify_dict and state == 'present':
            LOG.info("Modify SDS params.")
            modify_changed = self.modify_sds_attributes(sds_id, modify_dict,
                                                        create_changed)

        # get updated SDS details
        sds_details = self.get_sds_details(sds_id=sds_id)

        # add IPs to SDS
        # update IP's role for an SDS
        add_ip_changed = False
        update_role_changed = False
        if sds_details and state == 'present' \
                and sds_ip_state == "present-in-sds":
            self.validate_ip_parameter(sds_ip_list)
            ips_to_add, roles_to_update = self.identify_ip_role(
                sds_ip_list, sds_details, sds_ip_state)
            if ips_to_add:
                add_ip_changed = self.add_ip(sds_id, ips_to_add)
            if roles_to_update:
                update_role_changed = self.update_role(sds_id,
                                                       roles_to_update)

        # remove IPs from SDS
        remove_ip_changed = False
        if sds_details and state == 'present' \
                and sds_ip_state == "absent-in-sds":
            self.validate_ip_parameter(sds_ip_list)
            ips_to_remove = self.identify_ip_role(sds_ip_list, sds_details,
                                                  sds_ip_state)
            if ips_to_remove:
                remove_ip_changed = self.remove_ip(sds_id, ips_to_remove)

        # delete operation
        delete_changed = False
        if sds_details and state == 'absent':
            delete_changed = self.delete_sds(sds_id)

        if create_changed or modify_changed or add_ip_changed \
                or update_role_changed or remove_ip_changed or delete_changed:
            changed = True

        # Returning the updated SDS details
        if state == 'present':
            sds_details = self.show_output(sds_id)
            result['sds_details'] = sds_details
        result['changed'] = changed
        self.module.exit_json(**result)

    def show_output(self, sds_id):
        """Show SDS details
            :param sds_id: ID of the SDS
            :type sds_id: str
            :return: Details of SDS
            :rtype: dict
        """

        try:
            sds_details = self.powerflex_conn.sds.get(
                filter_fields={'id': sds_id})

            if len(sds_details) == 0:
                msg = "SDS with identifier '%s' not found" % sds_id
                LOG.error(msg)
                return None

            # Append protection domain name
            if 'protectionDomainId' in sds_details[0] \
                    and sds_details[0]['protectionDomainId']:
                pd_details = self.get_protection_domain(
                    protection_domain_id=sds_details[0]['protectionDomainId'])
                sds_details[0]['protectionDomainName'] = pd_details['name']

            # Append rmcache size in MB
            if 'rmcacheSizeInKb' in sds_details[0] \
                    and sds_details[0]['rmcacheSizeInKb']:
                rmcache_size_mb = sds_details[0]['rmcacheSizeInKb'] / 1024
                sds_details[0]['rmcacheSizeInMb'] = int(rmcache_size_mb)

            return sds_details[0]

        except Exception as e:
            error_msg = "Failed to get the SDS '%s' with error '%s'"\
                        % (sds_id, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)


def get_powerflex_sds_parameters():
    """This method provide parameter required for the SDS module on
    PowerFlex"""
    return dict(
        sds_name=dict(),
        sds_id=dict(),
        sds_new_name=dict(),
        protection_domain_name=dict(),
        protection_domain_id=dict(),
        sds_ip_list=dict(
            type='list', elements='dict', options=dict(
                ip=dict(required=True),
                role=dict(required=True, choices=['all', 'sdsOnly',
                                                  'sdcOnly'])
            )
        ),
        sds_ip_state=dict(choices=['present-in-sds', 'absent-in-sds']),
        rfcache_enabled=dict(type='bool'),
        rmcache_enabled=dict(type='bool'),
        rmcache_size=dict(type='int'),
        performance_profile=dict(choices=['Compact', 'HighPerformance']),
        state=dict(required=True, type='str', choices=['present', 'absent'])
    )


def main():
    """ Create PowerFlex SDS object and perform actions on it
        based on user input from playbook"""
    obj = PowerFlexSDS()
    obj.perform_module_operation()


if __name__ == '__main__':
    main()

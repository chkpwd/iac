#!/usr/bin/python

# Copyright: (c) 2021, Dell Technologies
# Apache License version 2.0 (see MODULE-LICENSE or http://www.apache.org/licenses/LICENSE-2.0.txt)

"""Ansible module for managing Dell Technologies (Dell) PowerFlex storage pool"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: storagepool

version_added: '1.0.0'

short_description: Managing Dell PowerFlex storage pool

description:
- Dell PowerFlex storage pool module includes getting the details of
  storage pool, creating a new storage pool, and modifying the attribute of
  a storage pool.

extends_documentation_fragment:
  - dellemc.powerflex.powerflex

author:
- Arindam Datta (@dattaarindam) <ansible.team@dell.com>
- P Srinivas Rao (@srinivas-rao5) <ansible.team@dell.com>

options:
  storage_pool_name:
    description:
    - The name of the storage pool.
    - If more than one storage pool is found with the same name then
      protection domain id/name is required to perform the task.
    - Mutually exclusive with I(storage_pool_id).
    type: str
  storage_pool_id:
    description:
    - The id of the storage pool.
    - It is auto generated, hence should not be provided during
      creation of a storage pool.
    - Mutually exclusive with I(storage_pool_name).
    type: str
  protection_domain_name:
    description:
    - The name of the protection domain.
    - During creation of a pool, either protection domain name or id must be
      mentioned.
    - Mutually exclusive with I(protection_domain_id).
    type: str
  protection_domain_id:
    description:
    - The id of the protection domain.
    - During creation of a pool, either protection domain name or id must
      be mentioned.
    - Mutually exclusive with I(protection_domain_name).
    type: str
  media_type:
    description:
    - Type of devices in the storage pool.
    type: str
    choices: ['HDD', 'SSD', 'TRANSITIONAL']
  storage_pool_new_name:
    description:
    - New name for the storage pool can be provided.
    - This parameter is used for renaming the storage pool.
    type: str
  use_rfcache:
    description:
    - Enable/Disable RFcache on a specific storage pool.
    type: bool
  use_rmcache:
    description:
    - Enable/Disable RMcache on a specific storage pool.
    type: bool
  state:
    description:
    - State of the storage pool.
    type: str
    choices: ["present", "absent"]
    required: true
notes:
  - TRANSITIONAL media type is supported only during modification.
  - The I(check_mode) is not supported.
'''

EXAMPLES = r'''

- name: Get the details of storage pool by name
  dellemc.powerflex.storagepool:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    storage_pool_name: "sample_pool_name"
    protection_domain_name: "sample_protection_domain"
    state: "present"

- name: Get the details of storage pool by id
  dellemc.powerflex.storagepool:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    storage_pool_id: "abcd1234ab12r"
    state: "present"

- name: Create a new storage pool by name
  dellemc.powerflex.storagepool:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    storage_pool_name: "ansible_test_pool"
    protection_domain_id: "1c957da800000000"
    media_type: "HDD"
    state: "present"

- name: Modify a storage pool by name
  dellemc.powerflex.storagepool:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    storage_pool_name: "ansible_test_pool"
    protection_domain_id: "1c957da800000000"
    use_rmcache: True
    use_rfcache: True
    state: "present"

- name: Rename storage pool by id
  dellemc.powerflex.storagepool:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    storage_pool_id: "abcd1234ab12r"
    storage_pool_new_name: "new_ansible_pool"
    state: "present"
'''

RETURN = r'''
changed:
    description: Whether or not the resource has changed.
    returned: always
    type: bool
    sample: 'false'
storage_pool_details:
    description: Details of the storage pool.
    returned: When storage pool exists
    type: dict
    contains:
        mediaType:
            description: Type of devices in the storage pool.
            type: str
        useRfcache:
            description: Enable/Disable RFcache on a specific storage pool.
            type: bool
        useRmcache:
            description: Enable/Disable RMcache on a specific storage pool.
            type: bool
        id:
            description: ID of the storage pool under protection domain.
            type: str
        name:
            description: Name of the storage pool under protection domain.
            type: str
        protectionDomainId:
            description: ID of the protection domain in which pool resides.
            type: str
        protectionDomainName:
            description: Name of the protection domain in which pool resides.
            type: str
        "statistics":
            description: Statistics details of the storage pool.
            type: dict
            contains:
                "capacityInUseInKb":
                    description: Total capacity of the storage pool.
                    type: str
                "unusedCapacityInKb":
                    description: Unused capacity of the storage pool.
                    type: str
                "deviceIds":
                    description: Device Ids of the storage pool.
                    type: list
    sample: {
        "addressSpaceUsage": "Normal",
        "addressSpaceUsageType": "DeviceCapacityLimit",
        "backgroundScannerBWLimitKBps": 3072,
        "backgroundScannerMode": "DataComparison",
        "bgScannerCompareErrorAction": "ReportAndFix",
        "bgScannerReadErrorAction": "ReportAndFix",
        "capacityAlertCriticalThreshold": 90,
        "capacityAlertHighThreshold": 80,
        "capacityUsageState": "Normal",
        "capacityUsageType": "NetCapacity",
        "checksumEnabled": false,
        "compressionMethod": "Invalid",
        "dataLayout": "MediumGranularity",
        "externalAccelerationType": "None",
        "fglAccpId": null,
        "fglExtraCapacity": null,
        "fglMaxCompressionRatio": null,
        "fglMetadataSizeXx100": null,
        "fglNvdimmMetadataAmortizationX100": null,
        "fglNvdimmWriteCacheSizeInMb": null,
        "fglOverProvisioningFactor": null,
        "fglPerfProfile": null,
        "fglWriteAtomicitySize": null,
        "fragmentationEnabled": true,
        "id": "e0d8f6c900000000",
        "links": [
            {
                "href": "/api/instances/StoragePool::e0d8f6c900000000",
                "rel": "self"
            },
            {
                "href": "/api/instances/StoragePool::e0d8f6c900000000
                        /relationships/Statistics",
                "rel": "/api/StoragePool/relationship/Statistics"
            },
            {
                "href": "/api/instances/StoragePool::e0d8f6c900000000
                        /relationships/SpSds",
                "rel": "/api/StoragePool/relationship/SpSds"
            },
            {
                "href": "/api/instances/StoragePool::e0d8f6c900000000
                        /relationships/Volume",
                "rel": "/api/StoragePool/relationship/Volume"
            },
            {
                "href": "/api/instances/StoragePool::e0d8f6c900000000
                        /relationships/Device",
                "rel": "/api/StoragePool/relationship/Device"
            },
            {
                "href": "/api/instances/StoragePool::e0d8f6c900000000
                        /relationships/VTree",
                "rel": "/api/StoragePool/relationship/VTree"
            },
            {
                "href": "/api/instances/ProtectionDomain::9300c1f900000000",
                "rel": "/api/parent/relationship/protectionDomainId"
            }
        ],
        "statistics": {
                "BackgroundScannedInMB": 3466920,
                "activeBckRebuildCapacityInKb": 0,
                "activeEnterProtectedMaintenanceModeCapacityInKb": 0,
                "aggregateCompressionLevel": "Uncompressed",
                "atRestCapacityInKb": 1248256,
                "backgroundScanCompareErrorCount": 0,
                "backgroundScanFixedCompareErrorCount": 0,
                "bckRebuildReadBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "bckRebuildWriteBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "capacityAvailableForVolumeAllocationInKb": 369098752,
                "capacityInUseInKb": 2496512,
                "capacityInUseNoOverheadInKb": 2496512,
                "capacityLimitInKb": 845783040,
                "compressedDataCompressionRatio": 0.0,
                "compressionRatio": 1.0,
                "currentFglMigrationSizeInKb": 0,
                "deviceIds": [
                ],
                "enterProtectedMaintenanceModeCapacityInKb": 0,
                "enterProtectedMaintenanceModeReadBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "enterProtectedMaintenanceModeWriteBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "exitProtectedMaintenanceModeReadBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "exitProtectedMaintenanceModeWriteBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "exposedCapacityInKb": 0,
                "failedCapacityInKb": 0,
                "fwdRebuildReadBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "fwdRebuildWriteBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "inMaintenanceCapacityInKb": 0,
                "inMaintenanceVacInKb": 0,
                "inUseVacInKb": 184549376,
                "inaccessibleCapacityInKb": 0,
                "logWrittenBlocksInKb": 0,
                "maxCapacityInKb": 845783040,
                "migratingVolumeIds": [
                ],
                "migratingVtreeIds": [
                ],
                "movingCapacityInKb": 0,
                "netCapacityInUseInKb": 1248256,
                "normRebuildCapacityInKb": 0,
                "normRebuildReadBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "normRebuildWriteBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "numOfDeviceAtFaultRebuilds": 0,
                "numOfDevices": 3,
                "numOfIncomingVtreeMigrations": 0,
                "numOfVolumes": 8,
                "numOfVolumesInDeletion": 0,
                "numOfVtrees": 8,
                "overallUsageRatio": 73.92289,
                "pendingBckRebuildCapacityInKb": 0,
                "pendingEnterProtectedMaintenanceModeCapacityInKb": 0,
                "pendingExitProtectedMaintenanceModeCapacityInKb": 0,
                "pendingFwdRebuildCapacityInKb": 0,
                "pendingMovingCapacityInKb": 0,
                "pendingMovingInBckRebuildJobs": 0,
                "persistentChecksumBuilderProgress": 100.0,
                "persistentChecksumCapacityInKb": 414720,
                "primaryReadBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "primaryReadFromDevBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "primaryReadFromRmcacheBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "primaryVacInKb": 92274688,
                "primaryWriteBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "protectedCapacityInKb": 2496512,
                "protectedVacInKb": 184549376,
                "provisionedAddressesInKb": 2496512,
                "rebalanceCapacityInKb": 0,
                "rebalanceReadBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "rebalanceWriteBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "rfacheReadHit": 0,
                "rfacheWriteHit": 0,
                "rfcacheAvgReadTime": 0,
                "rfcacheAvgWriteTime": 0,
                "rfcacheIoErrors": 0,
                "rfcacheIosOutstanding": 0,
                "rfcacheIosSkipped": 0,
                "rfcacheReadMiss": 0,
                "rmPendingAllocatedInKb": 0,
                "rmPendingThickInKb": 0,
                "rplJournalCapAllowed": 0,
                "rplTotalJournalCap": 0,
                "rplUsedJournalCap": 0,
                "secondaryReadBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "secondaryReadFromDevBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "secondaryReadFromRmcacheBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "secondaryVacInKb": 92274688,
                "secondaryWriteBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "semiProtectedCapacityInKb": 0,
                "semiProtectedVacInKb": 0,
                "snapCapacityInUseInKb": 0,
                "snapCapacityInUseOccupiedInKb": 0,
                "snapshotCapacityInKb": 0,
                "spSdsIds": [
                    "abdfe71b00030001",
                    "abdce71d00040001",
                    "abdde71e00050001"
                ],
                "spareCapacityInKb": 84578304,
                "targetOtherLatency": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "targetReadLatency": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "targetWriteLatency": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "tempCapacityInKb": 0,
                "tempCapacityVacInKb": 0,
                "thickCapacityInUseInKb": 0,
                "thinAndSnapshotRatio": 73.92289,
                "thinCapacityAllocatedInKm": 184549376,
                "thinCapacityInUseInKb": 0,
                "thinUserDataCapacityInKb": 2496512,
                "totalFglMigrationSizeInKb": 0,
                "totalReadBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "totalWriteBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "trimmedUserDataCapacityInKb": 0,
                "unreachableUnusedCapacityInKb": 0,
                "unusedCapacityInKb": 758708224,
                "userDataCapacityInKb": 2496512,
                "userDataCapacityNoTrimInKb": 2496512,
                "userDataReadBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "userDataSdcReadLatency": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "userDataSdcTrimLatency": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "userDataSdcWriteLatency": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "userDataTrimBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "userDataWriteBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "volMigrationReadBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "volMigrationWriteBwc": {
                    "numOccured": 0,
                    "numSeconds": 0,
                    "totalWeightInKb": 0
                },
                "volumeAddressSpaceInKb": 922XXXXX,
                "volumeAllocationLimitInKb": 3707XXXXX,
                "volumeIds": [
                    "456afc7900XXXXXXXX"
                ],
                "vtreeAddresSpaceInKb": 92274688,
                "vtreeIds": [
                    "32b1681bXXXXXXXX",
                ]
        },
        "mediaType": "HDD",
        "name": "pool1",
        "numOfParallelRebuildRebalanceJobsPerDevice": 2,
        "persistentChecksumBuilderLimitKb": 3072,
        "persistentChecksumEnabled": true,
        "persistentChecksumState": "Protected",
        "persistentChecksumValidateOnRead": false,
        "protectedMaintenanceModeIoPriorityAppBwPerDeviceThresholdInKbps": null,
        "protectedMaintenanceModeIoPriorityAppIopsPerDeviceThreshold": null,
        "protectedMaintenanceModeIoPriorityBwLimitPerDeviceInKbps": 10240,
        "protectedMaintenanceModeIoPriorityNumOfConcurrentIosPerDevice": 1,
        "protectedMaintenanceModeIoPriorityPolicy": "limitNumOfConcurrentIos",
        "protectedMaintenanceModeIoPriorityQuietPeriodInMsec": null,
        "protectionDomainId": "9300c1f900000000",
        "protectionDomainName": "domain1",
        "rebalanceEnabled": true,
        "rebalanceIoPriorityAppBwPerDeviceThresholdInKbps": null,
        "rebalanceIoPriorityAppIopsPerDeviceThreshold": null,
        "rebalanceIoPriorityBwLimitPerDeviceInKbps": 10240,
        "rebalanceIoPriorityNumOfConcurrentIosPerDevice": 1,
        "rebalanceIoPriorityPolicy": "favorAppIos",
        "rebalanceIoPriorityQuietPeriodInMsec": null,
        "rebuildEnabled": true,
        "rebuildIoPriorityAppBwPerDeviceThresholdInKbps": null,
        "rebuildIoPriorityAppIopsPerDeviceThreshold": null,
        "rebuildIoPriorityBwLimitPerDeviceInKbps": 10240,
        "rebuildIoPriorityNumOfConcurrentIosPerDevice": 1,
        "rebuildIoPriorityPolicy": "limitNumOfConcurrentIos",
        "rebuildIoPriorityQuietPeriodInMsec": null,
        "replicationCapacityMaxRatio": 32,
        "rmcacheWriteHandlingMode": "Cached",
        "sparePercentage": 10,
        "useRfcache": false,
        "useRmcache": false,
        "vtreeMigrationIoPriorityAppBwPerDeviceThresholdInKbps": null,
        "vtreeMigrationIoPriorityAppIopsPerDeviceThreshold": null,
        "vtreeMigrationIoPriorityBwLimitPerDeviceInKbps": 10240,
        "vtreeMigrationIoPriorityNumOfConcurrentIosPerDevice": 1,
        "vtreeMigrationIoPriorityPolicy": "favorAppIos",
        "vtreeMigrationIoPriorityQuietPeriodInMsec": null,
        "zeroPaddingEnabled": true
    }
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.powerflex.plugins.module_utils.storage.dell\
    import utils

LOG = utils.get_logger('storagepool')


class PowerFlexStoragePool(object):
    """Class with StoragePool operations"""

    def __init__(self):
        """ Define all parameters required by this module"""

        self.module_params = utils.get_powerflex_gateway_host_parameters()
        self.module_params.update(get_powerflex_storagepool_parameters())

        """ initialize the ansible module """
        mut_ex_args = [['storage_pool_name', 'storage_pool_id'],
                       ['protection_domain_name', 'protection_domain_id'],
                       ['storage_pool_id', 'protection_domain_name'],
                       ['storage_pool_id', 'protection_domain_id']]

        required_one_of_args = [['storage_pool_name', 'storage_pool_id']]
        self.module = AnsibleModule(argument_spec=self.module_params,
                                    supports_check_mode=False,
                                    mutually_exclusive=mut_ex_args,
                                    required_one_of=required_one_of_args)

        utils.ensure_required_libs(self.module)

        try:
            self.powerflex_conn = utils.get_powerflex_gateway_host_connection(
                self.module.params)
            LOG.info('Got the PowerFlex system connection object instance')
        except Exception as e:
            LOG.error(str(e))
            self.module.fail_json(msg=str(e))

    def get_protection_domain(self, protection_domain_name=None,
                              protection_domain_id=None):
        """Get protection domain details
            :param protection_domain_name: Name of the protection domain
            :param protection_domain_id: ID of the protection domain
            :return: Protection domain details
        """
        name_or_id = protection_domain_id if protection_domain_id \
            else protection_domain_name
        try:
            filter_fields = {}
            if protection_domain_id:
                filter_fields = {'id': protection_domain_id}
            if protection_domain_name:
                filter_fields = {'name': protection_domain_name}

            pd_details = self.powerflex_conn.protection_domain.get(
                filter_fields=filter_fields)
            if pd_details:
                return pd_details[0]

            if not pd_details:
                err_msg = "Unable to find the protection domain with {0}. " \
                          "Please enter a valid protection domain" \
                          " name/id.".format(name_or_id)
                self.module.fail_json(msg=err_msg)

        except Exception as e:
            errormsg = "Failed to get the protection domain {0} with" \
                       " error {1}".format(name_or_id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def get_storage_pool(self, storage_pool_id=None, storage_pool_name=None,
                         pd_id=None):
        """Get storage pool details
            :param pd_id: ID of the protection domain
            :param storage_pool_name: The name of the storage pool
            :param storage_pool_id: The storage pool id
            :return: Storage pool details
        """
        name_or_id = storage_pool_id if storage_pool_id \
            else storage_pool_name
        try:
            filter_fields = {}
            if storage_pool_id:
                filter_fields = {'id': storage_pool_id}
            if storage_pool_name:
                filter_fields.update({'name': storage_pool_name})
            if pd_id:
                filter_fields.update({'protectionDomainId': pd_id})
            pool_details = self.powerflex_conn.storage_pool.get(
                filter_fields=filter_fields)
            if pool_details:
                if len(pool_details) > 1:

                    err_msg = "More than one storage pool found with {0}," \
                              " Please provide protection domain Name/Id" \
                              " to fetch the unique" \
                              " storage pool".format(storage_pool_name)
                    LOG.error(err_msg)
                    self.module.fail_json(msg=err_msg)
                elif len(pool_details) == 1:
                    pool_details = pool_details[0]
                    statistics = self.powerflex_conn.storage_pool.get_statistics(pool_details['id'])
                    pool_details['statistics'] = statistics if statistics else {}
                    pd_id = pool_details['protectionDomainId']
                    pd_name = self.get_protection_domain(
                        protection_domain_id=pd_id)['name']
                    # adding protection domain name in the pool details
                    pool_details['protectionDomainName'] = pd_name
                else:
                    pool_details = None

            return pool_details

        except Exception as e:
            errormsg = "Failed to get the storage pool {0} with error " \
                       "{1}".format(name_or_id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def create_storage_pool(self, pool_name, pd_id, media_type,
                            use_rfcache=None, use_rmcache=None):
        """
        Create a storage pool
        :param pool_name: Name of the storage pool
        :param pd_id: ID of the storage pool
        :param media_type: Type of storage device in the pool
        :param use_rfcache: Enable/Disable RFcache on pool
        :param use_rmcache: Enable/Disable RMcache on pool
        :return: True, if the operation is successful
        """
        try:
            if media_type == "Transitional":
                self.module.fail_json(msg="TRANSITIONAL media type is not"
                                          " supported during creation."
                                          " Please enter a valid media type")

            if pd_id is None:
                self.module.fail_json(
                    msg="Please provide protection domain details for "
                        "creation of a storage pool")
            self.powerflex_conn.storage_pool.create(
                media_type=media_type,
                protection_domain_id=pd_id, name=pool_name,
                use_rfcache=use_rfcache, use_rmcache=use_rmcache)

            return True
        except Exception as e:
            errormsg = "Failed to create the storage pool {0} with error " \
                       "{1}".format(pool_name, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def modify_storage_pool(self, pool_id, modify_dict):
        """
        Modify the parameters of the storage pool.
        :param modify_dict: Dict containing parameters which are to be
         modified
        :param pool_id: Id of the pool.
        :return: True, if the operation is successful.
        """

        try:

            if 'new_name' in modify_dict:
                self.powerflex_conn.storage_pool.rename(
                    pool_id, modify_dict['new_name'])
            if 'use_rmcache' in modify_dict:
                self.powerflex_conn.storage_pool.set_use_rmcache(
                    pool_id, modify_dict['use_rmcache'])
            if 'use_rfcache' in modify_dict:
                self.powerflex_conn.storage_pool.set_use_rfcache(
                    pool_id, modify_dict['use_rfcache'])
            if 'media_type' in modify_dict:
                self.powerflex_conn.storage_pool.set_media_type(
                    pool_id, modify_dict['media_type'])
            return True

        except Exception as e:
            err_msg = "Failed to update the storage pool {0} with error " \
                      "{1}".format(pool_id, str(e))
            LOG.error(err_msg)
            self.module.fail_json(msg=err_msg)

    def verify_params(self, pool_details, pd_name, pd_id):
        """
        :param pool_details: Details of the storage pool
        :param pd_name: Name of the protection domain
        :param pd_id: Id of the protection domain
        """
        if pd_id and pd_id != pool_details['protectionDomainId']:
            self.module.fail_json(msg="Entered protection domain id does not"
                                      " match with the storage pool's "
                                      "protection domain id. Please enter "
                                      "a correct protection domain id.")

        if pd_name and pd_name != pool_details['protectionDomainName']:
            self.module.fail_json(msg="Entered protection domain name does"
                                      " not match with the storage pool's "
                                      "protection domain name. Please enter"
                                      " a correct protection domain name.")

    def perform_module_operation(self):
        """ Perform different actions on Storage Pool based on user input
            in the playbook """

        pool_name = self.module.params['storage_pool_name']
        pool_id = self.module.params['storage_pool_id']
        pool_new_name = self.module.params['storage_pool_new_name']
        state = self.module.params['state']
        pd_name = self.module.params['protection_domain_name']
        pd_id = self.module.params['protection_domain_id']
        use_rmcache = self.module.params['use_rmcache']
        use_rfcache = self.module.params['use_rfcache']
        media_type = self.module.params['media_type']
        if media_type == "TRANSITIONAL":
            media_type = 'Transitional'

        result = dict(
            storage_pool_details={}
        )
        changed = False
        pd_details = None
        if pd_name or pd_id:
            pd_details = self.get_protection_domain(
                protection_domain_id=pd_id,
                protection_domain_name=pd_name)
        if pd_details:
            pd_id = pd_details['id']

        if pool_name is not None and (len(pool_name.strip()) == 0):
            self.module.fail_json(
                msg="Empty or white spaced string provided in "
                    "storage_pool_name. Please provide valid storage"
                    " pool name.")

        # Get the details of the storage pool.
        pool_details = self.get_storage_pool(storage_pool_id=pool_id,
                                             storage_pool_name=pool_name,
                                             pd_id=pd_id)
        if pool_name and pool_details:
            pool_id = pool_details['id']
            self.verify_params(pool_details, pd_name, pd_id)

        # create a storage pool
        if state == 'present' and not pool_details:
            LOG.info("Creating new storage pool")
            if pool_id:
                self.module.fail_json(
                    msg="storage_pool_name is missing & name required to "
                        "create a storage pool. Please enter a valid "
                        "storage_pool_name.")
            if pool_new_name is not None:
                self.module.fail_json(
                    msg="storage_pool_new_name is passed during creation. "
                        "storage_pool_new_name is not allowed during "
                        "creation of a storage pool.")
            changed = self.create_storage_pool(
                pool_name, pd_id, media_type, use_rfcache, use_rmcache)
            if changed:
                pool_id = self.get_storage_pool(storage_pool_id=pool_id,
                                                storage_pool_name=pool_name,
                                                pd_id=pd_id)['id']

        # modify the storage pool parameters
        if state == 'present' and pool_details:
            # check if the parameters are to be updated or not
            if pool_new_name is not None and len(pool_new_name.strip()) == 0:
                self.module.fail_json(
                    msg="Empty/White spaced name is not allowed during "
                        "renaming of a storage pool. Please enter a valid "
                        "storage pool new name.")
            modify_dict = to_modify(pool_details, use_rmcache, use_rfcache,
                                    pool_new_name, media_type)
            if bool(modify_dict):
                LOG.info("Modify attributes of storage pool")
                changed = self.modify_storage_pool(pool_id, modify_dict)

        # Delete a storage pool
        if state == 'absent' and pool_details:
            msg = "Deleting storage pool is not supported through" \
                  " ansible module."
            LOG.error(msg)
            self.module.fail_json(msg=msg)

        # Show the updated storage pool details
        if state == 'present':
            pool_details = self.get_storage_pool(storage_pool_id=pool_id)
            # fetching Id from pool details to address a case where
            # protection domain is not passed
            pd_id = pool_details['protectionDomainId']
            pd_name = self.get_protection_domain(
                protection_domain_id=pd_id)['name']
            # adding protection domain name in the pool details
            pool_details['protectionDomainName'] = pd_name
            result['storage_pool_details'] = pool_details
        result['changed'] = changed

        self.module.exit_json(**result)


def to_modify(pool_details, use_rmcache, use_rfcache, new_name, media_type):
    """
    Check whether a parameter is required to be updated.

    :param media_type:  Type of the media supported by the pool.
    :param pool_details: Details of the storage pool
    :param use_rmcache: Enable/Disable RMcache on pool
    :param use_rfcache: Enable/Disable RFcache on pool
    :param new_name: New name for the storage pool
    :return: dict, containing parameters to be modified
    """
    pool_name = pool_details['name']
    pool_use_rfcache = pool_details['useRfcache']
    pool_use_rmcache = pool_details['useRmcache']
    pool_media_type = pool_details['mediaType']
    modify_params = {}

    if new_name is not None and pool_name != new_name:
        modify_params['new_name'] = new_name
    if use_rfcache is not None and pool_use_rfcache != use_rfcache:
        modify_params['use_rfcache'] = use_rfcache
    if use_rmcache is not None and pool_use_rmcache != use_rmcache:
        modify_params['use_rmcache'] = use_rmcache
    if media_type is not None and media_type != pool_media_type:
        modify_params['media_type'] = media_type
    return modify_params


def get_powerflex_storagepool_parameters():
    """This method provides parameters required for the ansible
    Storage Pool module on powerflex"""
    return dict(
        storage_pool_name=dict(required=False, type='str'),
        storage_pool_id=dict(required=False, type='str'),
        protection_domain_name=dict(required=False, type='str'),
        protection_domain_id=dict(required=False, type='str'),
        media_type=dict(required=False, type='str',
                        choices=['HDD', 'SSD', 'TRANSITIONAL']),
        use_rfcache=dict(required=False, type='bool'),
        use_rmcache=dict(required=False, type='bool'),
        storage_pool_new_name=dict(required=False, type='str'),
        state=dict(required=True, type='str', choices=['present', 'absent']))


def main():
    """ Create PowerFlex Storage Pool object and perform action on it
        based on user input from playbook"""
    obj = PowerFlexStoragePool()
    obj.perform_module_operation()


if __name__ == '__main__':
    main()

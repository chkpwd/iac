#!/usr/bin/python

# Copyright: (c) 2021, Dell Technologies
# Apache License version 2.0 (see MODULE-LICENSE or http://www.apache.org/licenses/LICENSE-2.0.txt)

"""Ansible module for Gathering information about Dell Technologies (Dell) PowerFlex"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: info

version_added: '1.0.0'

short_description: Gathering information about Dell PowerFlex

description:
- Gathering information about Dell PowerFlex storage system includes
  getting the api details, list of volumes, SDSs, SDCs, storage pools,
  protection domains, snapshot policies, and devices.

extends_documentation_fragment:
  - dellemc.powerflex.powerflex

author:
- Arindam Datta (@dattaarindam) <ansible.team@dell.com>

options:
  gather_subset:
    description:
    - List of string variables to specify the Powerflex storage system
      entities for which information is required.
    - Volumes - C(vol).
    - Storage pools - C(storage_pool).
    - Protection domains - C(protection_domain).
    - SDCs - C(sdc).
    - SDSs - C(sds).
    - Snapshot policies - C(snapshot_policy).
    - Devices - C(device).
    - Replication consistency groups - C(rcg).
    - Replication pairs - C(replication_pair).
    choices: [vol, storage_pool, protection_domain, sdc, sds,
             snapshot_policy, device, rcg, replication_pair]
    type: list
    elements: str
  filters:
    description:
    - List of filters to support filtered output for storage entities.
    - Each filter is a list of I(filter_key), I(filter_operator), I(filter_value).
    - Supports passing of multiple filters.
    type: list
    elements: dict
    suboptions:
      filter_key:
        description:
        - Name identifier of the filter.
        type: str
        required: true
      filter_operator:
        description:
        - Operation to be performed on filter key.
        type: str
        choices: [equal]
        required: true
      filter_value:
        description:
        - Value of the filter key.
        type: str
        required: true
notes:
  - The I(check_mode) is supported.
'''

EXAMPLES = r'''
- name: Get detailed list of PowerFlex entities
  dellemc.powerflex.info:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    gather_subset:
      - vol
      - storage_pool
      - protection_domain
      - sdc
      - sds
      - snapshot_policy
      - device
      - rcg
      - replication_pair

- name: Get a subset list of PowerFlex volumes
  dellemc.powerflex.info:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    gather_subset:
      - vol
    filters:
      - filter_key: "name"
        filter_operator: "equal"
        filter_value: "ansible_test"
'''

RETURN = r'''
changed:
    description: Whether or not the resource has changed.
    returned: always
    type: bool
    sample: 'false'
Array_Details:
    description: System entities of PowerFlex storage array.
    returned: always
    type: dict
    contains:
        addressSpaceUsage:
            description: Address space usage.
            type: str
        authenticationMethod:
            description: Authentication method.
            type: str
        capacityAlertCriticalThresholdPercent:
            description: Capacity alert critical threshold percentage.
            type: int
        capacityAlertHighThresholdPercent:
            description: Capacity alert high threshold percentage.
            type: int
        capacityTimeLeftInDays:
            description: Capacity time left in days.
            type: str
        cliPasswordAllowed:
            description: CLI password allowed.
            type: bool
        daysInstalled:
            description: Days installed.
            type: int
        defragmentationEnabled:
            description: Defragmentation enabled.
            type: bool
        enterpriseFeaturesEnabled:
            description: Enterprise features enabled.
            type: bool
        id:
            description: The ID of the system.
            type: str
        installId:
            description: installation Id.
            type: str
        isInitialLicense:
            description: Initial license.
            type: bool
        lastUpgradeTime:
            description: Last upgrade time.
            type: int
        managementClientSecureCommunicationEnabled:
            description: Management client secure communication enabled.
            type: bool
        maxCapacityInGb:
            description: Maximum capacity in GB.
            type: dict
        mdmCluster:
            description: MDM cluster details.
            type: dict
        mdmExternalPort:
            description: MDM external port.
            type: int
        mdmManagementPort:
            description: MDM management port.
            type: int
        mdmSecurityPolicy:
            description: MDM security policy.
            type: str
        showGuid:
            description: Show guid.
            type: bool
        swid:
            description: SWID.
            type: str
        systemVersionName:
            description: System version and name.
            type: str
        tlsVersion:
            description: TLS version.
            type: str
        upgradeState:
            description: Upgrade state.
            type: str
    sample: {
        "addressSpaceUsage": "Normal",
        "authenticationMethod": "Native",
        "capacityAlertCriticalThresholdPercent": 90,
        "capacityAlertHighThresholdPercent": 80,
        "capacityTimeLeftInDays": "24",
        "cliPasswordAllowed": true,
        "daysInstalled": 66,
        "defragmentationEnabled": true,
        "enterpriseFeaturesEnabled": true,
        "id": "4a54a8ba6df0690f",
        "installId": "38622771228e56db",
        "isInitialLicense": true,
        "lastUpgradeTime": 0,
        "managementClientSecureCommunicationEnabled": true,
        "maxCapacityInGb": "Unlimited",
        "mdmCluster": {
            "clusterMode": "ThreeNodes",
            "clusterState": "ClusteredNormal",
            "goodNodesNum": 3,
            "goodReplicasNum": 2,
            "id": "5356091375512217871",
            "master": {
                "id": "6101582c2ca8db00",
                "ips": [
                    "10.47.xxx.xxx"
                ],
                "managementIPs": [
                    "10.47.xxx.xxx"
                ],
                "name": "node0",
                "opensslVersion": "OpenSSL 1.0.2k-fips  26 Jan 2017",
                "port": 9011,
                "role": "Manager",
                "status": "Normal",
                "versionInfo": "R3_6.0.0",
                "virtualInterfaces": [
                    "ens160"
                ]
            },
            "slaves": [
                {
                    "id": "23fb724015661901",
                    "ips": [
                        "10.47.xxx.xxx"
                    ],
                    "managementIPs": [
                        "10.47.xxx.xxx"
                    ],
                    "opensslVersion": "OpenSSL 1.0.2k-fips  26 Jan 2017",
                    "port": 9011,
                    "role": "Manager",
                    "status": "Normal",
                    "versionInfo": "R3_6.0.0",
                    "virtualInterfaces": [
                        "ens160"
                    ]
                }
            ],
            "tieBreakers": [
                {
                    "id": "6ef27eb20d0c1202",
                    "ips": [
                        "10.47.xxx.xxx"
                    ],
                    "managementIPs": [
                        "10.47.xxx.xxx"
                    ],
                    "opensslVersion": "N/A",
                    "port": 9011,
                    "role": "TieBreaker",
                    "status": "Normal",
                    "versionInfo": "R3_6.0.0"
                }
            ]
        },
        "mdmExternalPort": 7611,
        "mdmManagementPort": 6611,
        "mdmSecurityPolicy": "None",
        "showGuid": true,
        "swid": "",
        "systemVersionName": "DellEMC PowerFlex Version: R3_6.0.354",
        "tlsVersion": "TLSv1.2",
        "upgradeState": "NoUpgrade"
    }
API_Version:
    description: API version of PowerFlex API Gateway.
    returned: always
    type: str
    sample: "3.5"
Protection_Domains:
    description: Details of all protection domains.
    returned: always
    type: list
    contains:
        id:
            description: protection domain id.
            type: str
        name:
            description: protection domain name.
            type: str
    sample: [
        {
            "id": "9300e90900000001",
            "name": "domain2"
        },
        {
            "id": "9300c1f900000000",
            "name": "domain1"
        }
    ]
SDCs:
    description: Details of storage data clients.
    returned: always
    type: list
    contains:
        id:
            description: storage data client id.
            type: str
        name:
            description: storage data client name.
            type: str
    sample: [
        {
            "id": "07335d3d00000006",
            "name": "LGLAP203"
        },
        {
            "id": "07335d3c00000005",
            "name": "LGLAP178"
        },
        {
            "id": "0733844a00000003"
        }
    ]
SDSs:
    description: Details of storage data servers.
    returned: always
    type: list
    contains:
        id:
            description: storage data server id.
            type: str
        name:
            description: storage data server name.
            type: str
    sample: [
        {
            "id": "8f3bb0cc00000002",
            "name": "node0"
        },
        {
            "id": "8f3bb0ce00000000",
            "name": "node1"
        },
        {
            "id": "8f3bb15300000001",
            "name": "node22"
        }
    ]
Snapshot_Policies:
    description: Details of snapshot policies.
    returned: always
    type: list
    contains:
        id:
            description: snapshot policy id.
            type: str
        name:
            description: snapshot policy name.
            type: str
    sample: [
        {
            "id": "2b380c5c00000000",
            "name": "sample_snap_policy"
        },
        {
            "id": "2b380c5d00000001",
            "name": "sample_snap_policy_1"
        }
    ]
Storage_Pools:
    description: Details of storage pools.
    returned: always
    type: list
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
        statistics:
            description: Statistics details of the storage pool.
            type: dict
            contains:
                capacityInUseInKb:
                    description: Total capacity of the storage pool.
                    type: str
                unusedCapacityInKb:
                    description: Unused capacity of the storage pool.
                    type: str
                deviceIds:
                    description: Device Ids of the storage pool.
                    type: list
    sample: [
        {
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
    ]
Volumes:
    description: Details of volumes.
    returned: always
    type: list
    contains:
        id:
            description: The ID of the volume.
            type: str
        mappedSdcInfo:
            description: The details of the mapped SDC.
            type: dict
            contains:
                sdcId:
                    description: ID of the SDC.
                    type: str
                sdcName:
                    description: Name of the SDC.
                    type: str
                sdcIp:
                    description: IP of the SDC.
                    type: str
                accessMode:
                    description: mapping access mode for the specified volume.
                    type: str
                limitIops:
                    description: IOPS limit for the SDC.
                    type: int
                limitBwInMbps:
                    description: Bandwidth limit for the SDC.
                    type: int
        name:
            description: Name of the volume.
            type: str
        sizeInKb:
            description: Size of the volume in Kb.
            type: int
        sizeInGb:
            description: Size of the volume in Gb.
            type: int
        storagePoolId:
            description: ID of the storage pool in which volume resides.
            type: str
        storagePoolName:
            description: Name of the storage pool in which volume resides.
            type: str
        protectionDomainId:
            description: ID of the protection domain in which volume resides.
            type: str
        protectionDomainName:
            description: Name of the protection domain in which volume resides.
            type: str
        snapshotPolicyId:
            description: ID of the snapshot policy associated with volume.
            type: str
        snapshotPolicyName:
            description: Name of the snapshot policy associated with volume.
            type: str
        snapshotsList:
            description: List of snapshots associated with the volume.
            type: str
        "statistics":
            description: Statistics details of the storage pool.
            type: dict
            contains:
                "numOfChildVolumes":
                    description: Number of child volumes.
                    type: int
                "numOfMappedSdcs":
                    description: Number of mapped Sdcs of the volume.
                    type: int
    sample: [
        {
            "accessModeLimit": "ReadWrite",
            "ancestorVolumeId": null,
            "autoSnapshotGroupId": null,
            "compressionMethod": "Invalid",
            "consistencyGroupId": null,
            "creationTime": 1661234220,
            "dataLayout": "MediumGranularity",
            "id": "456afd7XXXXXXX",
            "lockedAutoSnapshot": false,
            "lockedAutoSnapshotMarkedForRemoval": false,
            "managedBy": "ScaleIO",
            "mappedSdcInfo": [
                {
                "accessMode": "ReadWrite",
                "isDirectBufferMapping": false,
                "limitBwInMbps": 0,
                "limitIops": 0,
                "sdcId": "c42425cbXXXXX",
                "sdcIp": "10.XXX.XX.XX",
                "sdcName": null
                }
            ],
            "name": "vol-1",
            "notGenuineSnapshot": false,
            "originalExpiryTime": 0,
            "pairIds": null,
            "replicationJournalVolume": false,
            "replicationTimeStamp": 0,
            "retentionLevels": [
            ],
            "secureSnapshotExpTime": 0,
            "sizeInKb": 8388608,
            "snplIdOfAutoSnapshot": null,
            "snplIdOfSourceVolume": null,
            "statistics": {
                "childVolumeIds": [
                ],
                "descendantVolumeIds": [
                ],
                "initiatorSdcId": null,
                "mappedSdcIds": [
                "c42425XXXXXX"
                ],
                "numOfChildVolumes": 0,
                "numOfDescendantVolumes": 0,
                "numOfMappedSdcs": 1,
                "registrationKey": null,
                "registrationKeys": [
                ],
                "replicationJournalVolume": false,
                "replicationState": "UnmarkedForReplication",
                "reservationType": "NotReserved",
                "rplTotalJournalCap": 0,
                "rplUsedJournalCap": 0,
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
                }
            },
            "storagePoolId": "7630a248XXXXXXX",
            "timeStampIsAccurate": false,
            "useRmcache": false,
            "volumeReplicationState": "UnmarkedForReplication",
            "volumeType": "ThinProvisioned",
            "vtreeId": "32b168bXXXXXX"
        }
    ]
Devices:
    description: Details of devices.
    returned: always
    type: list
    contains:
        id:
            description: device id.
            type: str
        name:
            description: device name.
            type: str
    sample:  [
        {
            "id": "b6efa59900000000",
            "name": "device230"
        },
        {
            "id": "b6efa5fa00020000",
            "name": "device_node0"
        },
        {
            "id": "b7f3a60900010000",
            "name": "device22"
        }
    ]
Replication_Consistency_Groups:
    description: Details of rcgs.
    returned: always
    type: list
    contains:
        id:
            description: The ID of the replication consistency group.
            type: str
        name:
            description: The name of the replication consistency group.
            type: str
        protectionDomainId:
            description: The Protection Domain ID of the replication consistency group.
            type: str
        peerMdmId:
            description: The ID of the peer MDM of the replication consistency group.
            type: str
        remoteId:
            description: The ID of the remote replication consistency group.
            type: str
        remoteMdmId:
            description: The ID of the remote MDM of the replication consistency group.
            type: str
        currConsistMode:
            description: The current consistency mode of the replication consistency group.
            type: str
        freezeState:
            description: The freeze state of the replication consistency group.
            type: str
        lifetimeState:
            description: The Lifetime state of the replication consistency group.
            type: str
        pauseMode:
            description: The Lifetime state of the replication consistency group.
            type: str
        snapCreationInProgress:
            description: Whether the process of snapshot creation of the replication consistency group is in progress or not.
            type: bool
        lastSnapGroupId:
            description: ID of the last snapshot of the replication consistency group.
            type: str
        lastSnapCreationRc:
            description: The return code of the last snapshot of the replication consistency group.
            type: int
        targetVolumeAccessMode:
            description: The access mode of the target volume of the replication consistency group.
            type: str
        remoteProtectionDomainId:
            description: The ID of the remote Protection Domain.
            type: str
        remoteProtectionDomainName:
            description: The Name of the remote Protection Domain.
            type: str
        failoverType:
            description: The type of failover of the replication consistency group.
            type: str
        failoverState:
            description: The state of failover of the replication consistency group.
            type: str
        activeLocal:
            description: Whether the local replication consistency group is active.
            type: bool
        activeRemote:
            description: Whether the remote replication consistency group is active
            type: bool
        abstractState:
            description: The abstract state of the replication consistency group.
            type: str
        localActivityState:
            description: The state of activity of the local replication consistency group.
            type: str
        remoteActivityState:
            description: The state of activity of the remote replication consistency group..
            type: str
        inactiveReason:
            description: The reason for the inactivity of the replication consistency group.
            type: int
        rpoInSeconds:
            description: The RPO value of the replication consistency group in seconds.
            type: int
        replicationDirection:
            description: The direction of the replication of the replication consistency group.
            type: str
        disasterRecoveryState:
            description: The state of disaster recovery of the local replication consistency group.
            type: str
        remoteDisasterRecoveryState:
            description: The state of disaster recovery of the remote replication consistency group.
            type: str
        error:
            description: The error code of the replication consistency group.
            type: int
        type:
            description: The type of the replication consistency group.
            type: str
    sample: {
        "protectionDomainId": "b969400500000000",
        "peerMdmId": "6c3d94f600000000",
        "remoteId": "2130961a00000000",
        "remoteMdmId": "0e7a082862fedf0f",
        "currConsistMode": "Consistent",
        "freezeState": "Unfrozen",
        "lifetimeState": "Normal",
        "pauseMode": "None",
        "snapCreationInProgress": false,
        "lastSnapGroupId": "e58280b300000001",
        "lastSnapCreationRc": "SUCCESS",
        "targetVolumeAccessMode": "NoAccess",
        "remoteProtectionDomainId": "4eeb304600000000",
        "remoteProtectionDomainName": "domain1",
        "failoverType": "None",
        "failoverState": "None",
        "activeLocal": true,
        "activeRemote": true,
        "abstractState": "Ok",
        "localActivityState": "Active",
        "remoteActivityState": "Active",
        "inactiveReason": 11,
        "rpoInSeconds": 30,
        "replicationDirection": "LocalToRemote",
        "disasterRecoveryState": "None",
        "remoteDisasterRecoveryState": "None",
        "error": 65,
        "name": "test_rcg",
        "type": "User",
        "id": "aadc17d500000000"
    }
Replication_pairs:
    description: Details of the replication pairs.
    returned: Always
    type: list
    contains:
        id:
            description: The ID of the replication pair.
            type: str
        name:
            description: The name of the replication pair.
            type: str
        remoteId:
            description: The ID of the remote replication pair.
            type: str
        localVolumeId:
            description: The ID of the local volume.
            type: str
        replicationConsistencyGroupId:
            description: The ID of the replication consistency group.
            type: str
        copyType:
            description: The copy type of the replication pair.
            type: str
        initialCopyState:
            description: The inital copy state of the replication pair.
            type: str
        localActivityState:
            description: The state of activity of the local replication pair.
            type: str
        remoteActivityState:
            description: The state of activity of the remote replication pair.
            type: str
    sample: {
        "copyType": "OnlineCopy",
        "id": "23aa0bc900000001",
        "initialCopyPriority": -1,
        "initialCopyState": "Done",
        "lifetimeState": "Normal",
        "localActivityState": "RplEnabled",
        "localVolumeId": "e2bc1fab00000008",
        "name": null,
        "peerSystemName": null,
        "remoteActivityState": "RplEnabled",
        "remoteCapacityInMB": 8192,
        "remoteId": "a058446700000001",
        "remoteVolumeId": "1cda7af20000000d",
        "remoteVolumeName": "vol",
        "replicationConsistencyGroupId": "e2ce036b00000002",
        "userRequestedPauseTransmitInitCopy": false
    }
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.powerflex.plugins.module_utils.storage.dell \
    import utils

LOG = utils.get_logger('info')


class PowerFlexInfo(object):
    """Class with Info operations"""

    filter_mapping = {'equal': 'eq.'}

    def __init__(self):
        """ Define all parameters required by this module"""

        self.module_params = utils.get_powerflex_gateway_host_parameters()
        self.module_params.update(get_powerflex_info_parameters())

        self.filter_keys = sorted(
            [k for k in self.module_params['filters']['options'].keys()
             if 'filter' in k])

        """ initialize the ansible module """
        self.module = AnsibleModule(argument_spec=self.module_params,
                                    supports_check_mode=True)

        utils.ensure_required_libs(self.module)

        try:
            self.powerflex_conn = utils.get_powerflex_gateway_host_connection(
                self.module.params)
            LOG.info('Got the PowerFlex system connection object instance')
            LOG.info('The check_mode flag %s', self.module.check_mode)

        except Exception as e:
            LOG.error(str(e))
            self.module.fail_json(msg=str(e))

    def get_api_details(self):
        """ Get api details of the array """
        try:
            LOG.info('Getting API details ')
            api_version = self.powerflex_conn.system.api_version()
            return api_version

        except Exception as e:
            msg = 'Get API details from Powerflex array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_array_details(self):
        """ Get system details of a powerflex array """

        try:
            LOG.info('Getting array details ')
            entity_list = ['addressSpaceUsage', 'authenticationMethod',
                           'capacityAlertCriticalThresholdPercent',
                           'capacityAlertHighThresholdPercent',
                           'capacityTimeLeftInDays', 'cliPasswordAllowed',
                           'daysInstalled', 'defragmentationEnabled',
                           'enterpriseFeaturesEnabled', 'id', 'installId',
                           'isInitialLicense', 'lastUpgradeTime',
                           'managementClientSecureCommunicationEnabled',
                           'maxCapacityInGb', 'mdmCluster',
                           'mdmExternalPort', 'mdmManagementPort',
                           'mdmSecurityPolicy', 'showGuid', 'swid',
                           'systemVersionName', 'tlsVersion', 'upgradeState']

            sys_list = self.powerflex_conn.system.get()
            sys_details_list = []
            for sys in sys_list:
                sys_details = {}
                for entity in entity_list:
                    if entity in sys.keys():
                        sys_details.update({entity: sys[entity]})
                if sys_details:
                    sys_details_list.append(sys_details)

            return sys_details_list

        except Exception as e:
            msg = 'Get array details from Powerflex array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_sdc_list(self, filter_dict=None):
        """ Get the list of sdcs on a given PowerFlex storage system """

        try:
            LOG.info('Getting SDC list ')
            if filter_dict:
                sdc = self.powerflex_conn.sdc.get(filter_fields=filter_dict)
            else:
                sdc = self.powerflex_conn.sdc.get()
            return result_list(sdc)

        except Exception as e:
            msg = 'Get SDC list from powerflex array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_sds_list(self, filter_dict=None):
        """ Get the list of sdses on a given PowerFlex storage system """

        try:
            LOG.info('Getting SDS list ')
            if filter_dict:
                sds = self.powerflex_conn.sds.get(filter_fields=filter_dict)
            else:
                sds = self.powerflex_conn.sds.get()
            return result_list(sds)

        except Exception as e:
            msg = 'Get sds list from powerflex array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_pd_list(self, filter_dict=None):
        """ Get the list of Protection Domains on a given PowerFlex
            storage system """

        try:
            LOG.info('Getting protection domain list ')

            if filter_dict:
                pd = self.powerflex_conn.protection_domain.get(filter_fields=filter_dict)
            else:
                pd = self.powerflex_conn.protection_domain.get()
            return result_list(pd)

        except Exception as e:
            msg = 'Get protection domain list from powerflex array failed ' \
                  'with error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_storage_pool_list(self, filter_dict=None):
        """ Get the list of storage pools on a given PowerFlex storage
            system """

        try:
            LOG.info('Getting storage pool list ')
            if filter_dict:
                pool = self.powerflex_conn.storage_pool.get(filter_fields=filter_dict)
            else:
                pool = self.powerflex_conn.storage_pool.get()

            if pool:
                statistics_map = self.powerflex_conn.utility.get_statistics_for_all_storagepools()
                list_of_pool_ids_in_statistics = statistics_map.keys()
                for item in pool:
                    item['statistics'] = statistics_map[item['id']] if item['id'] in list_of_pool_ids_in_statistics else {}
            return result_list(pool)

        except Exception as e:
            msg = 'Get storage pool list from powerflex array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_replication_consistency_group_list(self, filter_dict=None):
        """ Get the list of replication consistency group on a given PowerFlex storage
            system """

        try:
            LOG.info('Getting replication consistency group list ')
            if filter_dict:
                rcgs = self.powerflex_conn.replication_consistency_group.get(filter_fields=filter_dict)
            else:
                rcgs = self.powerflex_conn.replication_consistency_group.get()
            if rcgs:
                api_version = self.powerflex_conn.system.get()[0]['mdmCluster']['master']['versionInfo']
                statistics_map = \
                    self.powerflex_conn.replication_consistency_group.get_all_statistics(utils.is_version_less_than_3_6(api_version))
                list_of_rcg_ids_in_statistics = statistics_map.keys()
                for rcg in rcgs:
                    rcg.pop('links', None)
                    rcg['statistics'] = statistics_map[rcg['id']] if rcg['id'] in list_of_rcg_ids_in_statistics else {}
                return result_list(rcgs)

        except Exception as e:
            msg = 'Get replication consistency group list from powerflex array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_replication_pair_list(self, filter_dict=None):
        """ Get the list of replication pairs on a given PowerFlex storage
            system """

        try:
            LOG.info('Getting replication pair list ')
            if filter_dict:
                pairs = self.powerflex_conn.replication_pair.get(filter_fields=filter_dict)
            else:
                pairs = self.powerflex_conn.replication_pair.get()
            if pairs:
                for pair in pairs:
                    pair.pop('links', None)
                    local_volume = self.powerflex_conn.volume.get(filter_fields={'id': pair['localVolumeId']})
                    if local_volume:
                        pair['localVolumeName'] = local_volume[0]['name']
                    pair['replicationConsistencyGroupName'] = \
                        self.powerflex_conn.replication_consistency_group.get(filter_fields={'id': pair['replicationConsistencyGroupId']})[0]['name']
                    pair['statistics'] = self.powerflex_conn.replication_pair.get_statistics(pair['id'])
                return pairs

        except Exception as e:
            msg = 'Get replication pair list from powerflex array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_volumes_list(self, filter_dict=None):
        """ Get the list of volumes on a given PowerFlex storage
            system """

        try:
            LOG.info('Getting volumes list ')
            if filter_dict:
                volumes = self.powerflex_conn.volume.get(filter_fields=filter_dict)
            else:
                volumes = self.powerflex_conn.volume.get()

            if volumes:
                statistics_map = self.powerflex_conn.utility.get_statistics_for_all_volumes()
                list_of_vol_ids_in_statistics = statistics_map.keys()
                for item in volumes:
                    item['statistics'] = statistics_map[item['id']] if item['id'] in list_of_vol_ids_in_statistics else {}
            return result_list(volumes)

        except Exception as e:
            msg = 'Get volumes list from powerflex array failed with' \
                  ' error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_snapshot_policy_list(self, filter_dict=None):
        """ Get the list of snapshot schedules on a given PowerFlex storage
            system """

        try:
            LOG.info('Getting snapshot schedules list ')
            if filter_dict:
                snapshot_schedules = \
                    self.powerflex_conn.snapshot_policy.get(
                        filter_fields=filter_dict)
            else:
                snapshot_schedules = \
                    self.powerflex_conn.snapshot_policy.get()

            return result_list(snapshot_schedules)

        except Exception as e:
            msg = 'Get snapshot schedules list from powerflex array failed ' \
                  'with error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_devices_list(self, filter_dict=None):
        """ Get the list of devices on a given PowerFlex storage
            system """

        try:
            LOG.info('Getting device list ')
            if filter_dict:
                devices = self.powerflex_conn.device.get(filter_fields=filter_dict)
            else:
                devices = self.powerflex_conn.device.get()

            return result_list(devices)

        except Exception as e:
            msg = 'Get device list from powerflex array failed ' \
                  'with error %s' % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def validate_filter(self, filter_dict):
        """ Validate given filter_dict """

        is_invalid_filter = self.filter_keys != sorted(list(filter_dict))
        if is_invalid_filter:
            msg = "Filter should have all keys: '{0}'".format(
                ", ".join(self.filter_keys))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

        is_invalid_filter = [filter_dict[i] is None for i in filter_dict]
        if True in is_invalid_filter:
            msg = "Filter keys: '{0}' cannot be None".format(self.filter_keys)
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_filters(self, filters):
        """Get the filters to be applied"""

        filter_dict = {}
        for item in filters:
            self.validate_filter(item)
            f_op = item['filter_operator']
            if self.filter_mapping.get(f_op):
                f_key = item['filter_key']
                f_val = item['filter_value']
                if f_key in filter_dict:
                    # multiple filters on same key
                    if isinstance(filter_dict[f_key], list):
                        # prev_val is list, so append new f_val
                        filter_dict[f_key].append(f_val)
                    else:
                        # prev_val is not list,
                        # so create list with prev_val & f_val
                        filter_dict[f_key] = [filter_dict[f_key], f_val]
                else:
                    filter_dict[f_key] = f_val
            else:
                msg = "Given filter operator '{0}' is not supported." \
                    "supported operators are : '{1}'".format(
                        f_op,
                        list(self.filter_mapping.keys()))
                LOG.error(msg)
                self.module.fail_json(msg=msg)
        return filter_dict

    def perform_module_operation(self):
        """ Perform different actions on info based on user input
            in the playbook """

        filters = self.module.params['filters']
        filter_dict = {}
        if filters:
            filter_dict = self.get_filters(filters)
            LOG.info('filters: %s', filter_dict)

        api_version = self.get_api_details()
        array_details = self.get_array_details()
        sdc = []
        sds = []
        storage_pool = []
        vol = []
        snapshot_policy = []
        protection_domain = []
        device = []
        rcgs = []
        replication_pair = []

        subset = self.module.params['gather_subset']
        if subset is not None:
            if 'sdc' in subset:
                sdc = self.get_sdc_list(filter_dict=filter_dict)
            if 'sds' in subset:
                sds = self.get_sds_list(filter_dict=filter_dict)
            if 'protection_domain' in subset:
                protection_domain = self.get_pd_list(filter_dict=filter_dict)
            if 'storage_pool' in subset:
                storage_pool = self.get_storage_pool_list(filter_dict=filter_dict)
            if 'vol' in subset:
                vol = self.get_volumes_list(filter_dict=filter_dict)
            if 'snapshot_policy' in subset:
                snapshot_policy = self.get_snapshot_policy_list(filter_dict=filter_dict)
            if 'device' in subset:
                device = self.get_devices_list(filter_dict=filter_dict)
            if 'rcg' in subset:
                rcgs = self.get_replication_consistency_group_list(filter_dict=filter_dict)
            if 'replication_pair' in subset:
                replication_pair = self.get_replication_pair_list(filter_dict=filter_dict)

        self.module.exit_json(
            Array_Details=array_details,
            API_Version=api_version,
            SDCs=sdc,
            SDSs=sds,
            Storage_Pools=storage_pool,
            Volumes=vol,
            Snapshot_Policies=snapshot_policy,
            Protection_Domains=protection_domain,
            Devices=device,
            Replication_Consistency_Groups=rcgs,
            Replication_Pairs=replication_pair
        )


def result_list(entity):
    """ Get the name and id associated with the PowerFlex entities """
    result = []
    if entity:
        LOG.info('Successfully listed.')
        for item in entity:
            if item['name']:
                result.append(item)
            else:
                result.append({"id": item['id']})
        return result
    else:
        return None


def get_powerflex_info_parameters():
    """This method provides parameters required for the ansible
    info module on powerflex"""
    return dict(
        gather_subset=dict(type='list', required=False, elements='str',
                           choices=['vol', 'storage_pool',
                                    'protection_domain', 'sdc', 'sds',
                                    'snapshot_policy', 'device', 'rcg', 'replication_pair']),
        filters=dict(type='list', required=False, elements='dict',
                     options=dict(filter_key=dict(type='str', required=True, no_log=False),
                                  filter_operator=dict(
                                      type='str', required=True,
                                      choices=['equal']),
                                  filter_value=dict(type='str', required=True)
                                  )))


def main():
    """ Create PowerFlex info object and perform action on it
        based on user input from playbook"""
    obj = PowerFlexInfo()
    obj.perform_module_operation()


if __name__ == '__main__':
    main()

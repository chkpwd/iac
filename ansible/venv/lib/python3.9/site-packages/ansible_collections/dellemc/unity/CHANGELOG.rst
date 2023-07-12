===========================
Dellemc.Unity Change Log
===========================

.. contents:: Topics


v1.6.0
======

Minor Changes
-------------

- Support addition of host from the Host List to NFS Export in nfs module.
- Support enable/disable advanced dedup in volume module.
- Add synchronous replication support for filesystem.

v1.5.0
======

Minor Changes
-------------

- Updated modules to adhere with ansible community guidelines.

v1.4.1
======

Minor Changes
-------------

- Updated the execution environment related files.

v1.4.0
======

Minor Changes
-------------

- Added cifsserver module to support create, list and delete CIFS server.
- Added execution environment manifest file to support building an execution environment with ansible-builder.
- Added interface module to support create, list and delete interface.
- Added nfsserver module to support create, list and delete NFS server.
- Check mode is supported for Info.
- Enhance nfs module to support advanced host management option.
- Enhanced filesystem module to support create, modify and delete of filesystem replication.
- Enhanced info module to list cifs server, nfs servers, ethernet port and file interface.
- Enhanced nas server module to support create, modify and delete of nas server replication.

New Modules
-----------

- dellemc.unity.cifsserver - Manage CIFS server on Unity storage system
- dellemc.unity.interface - Manage Interfaces on Unity storage system
- dellemc.unity.nfsserver - Manage NFS server on Unity storage system

v1.3.0
======

Minor Changes
-------------

- Added rotating file handler for logging.
- Bugfix in volume module to retrieve details of non-thin volumes.
- Enhance host module to support add/remove network address to/from a host.
- Enhanced Info module to list disk groups.
- Enhanced Storage Pool module to support listing of drive details of a pool
- Enhanced Storage pool module to support creation of storage pool
- Enhanced consistency group module to support enable/disable replication in consistency group
- Enhanced host module to support both mapping and un-mapping of non-logged-in initiators to host.
- Enhanced host module to support listing of network addresses, FC initiators, ISCSI initiators and allocated volumes of a host
- Removed dellemc.unity prefix from module names.
- Renamed gatherfacts module to info module

v1.2.1
======

Minor Changes
-------------

- Added dual licensing
- Documentation updates
- Fixed typo in galaxy.yml
- Updated few samples in modules

v1.2.0
======

Minor Changes
-------------

- Added CRUD operations support for Quota tree.
- Added CRUD operations support for User Quota on Filesystem/Quota tree.
- Added support for Application tagging.
- Consistency group module is enhanced to map/unmap hosts to/from a new or existing consistency group.
- Filesystem module is enhanced to associate/dissociate snapshot schedule to/from a Filesystem.
- Filesystem module is enhanced to update default quota configuration during create operation.
- Gather facts module is enhanced to list User Quota and Quota tree components.
- Volume module is enhanced to support map/unmap multiple hosts from a volume.

New Modules
-----------

- dellemc.unity.tree_quota - Manage quota tree on the Unity storage system
- dellemc.unity.user_quota - Manage user quota on the Unity storage system

v1.1.0
======

Minor Changes
-------------

- Added CRUD operations support for Filesystem snapshot.
- Added CRUD operations support for Filesystem.
- Added CRUD operations support for NFS export.
- Added CRUD operations support for SMB share.
- Added support to get/modify operations on NAS server.
- Gather facts module is enhanced to list Filesystem snapshots, NAS servers, File systems, NFS exports, SMB shares.

New Modules
-----------

- dellemc.unity.filesystem - Manage filesystem on Unity storage system
- dellemc.unity.filesystem_snapshot - Manage filesystem snapshot on the Unity storage system
- dellemc.unity.nasserver - Manage NAS servers on Unity storage system
- dellemc.unity.nfs - Manage NFS export on Unity storage system
- dellemc.unity.smbshare - Manage SMB shares on Unity storage system

v1.0.0
======

Major Changes
-------------

- Added CRUD operations support for Consistency group.
- Added CRUD operations support for Volume.
- Added CRUD operations support for a snapshot schedule.
- Added support for CRUD operations on a host with FC/iSCSI initiators.
- Added support for CRUD operations on a snapshot of a volume.
- Added support for adding/removing volumes to/from a consistency group.
- Added support to add/remove FC/iSCSI initiators to/from a host.
- Added support to create a snapshot for a consistency group.
- Added support to get/modify operations on storage pool.
- Added support to map/unmap a host to/from a snapshot.
- Gather facts module is enhanced to list volumes, consistency groups, FC initiators, iSCSI initiators, hosts, snapshot schedules.

New Modules
-----------

- dellemc.unity.consistencygroup - Manage consistency groups on Unity storage system
- dellemc.unity.host - Manage Host operations on Unity
- dellemc.unity.info - Gathering information about Unity
- dellemc.unity.snapshot - Manage snapshots on the Unity storage system
- dellemc.unity.snapshotschedule - Manage snapshot schedules on Unity storage system
- dellemc.unity.storagepool - Manage storage pool on Unity
- dellemc.unity.volume - Manage volume on Unity storage system

Objective:
Migrate volume from one Flash System to another Flash System in application transparent manner.

Prerequisite:
- IBM Spectrum Virtualize and Brocade ansible collection plugins must be installed
- For more information on Brocade switch ansible collection, please refer to https://github.com/brocade/ansible/blob/master/README.rst

These playbooks migrate a volume from a source cluster to the destination cluster.
  - It uses spectrum virtualize ansible modules as well as brocade ansible modules to create zone.
  - These playbooks are designed to migrate volume mapped to same Fibre Channel (FC) host from source cluster to destination cluster.
  
There are total 3 files used for this use-case.
  1. vol_migration_vars:
     This file has all the variables required for playbooks.
	 - src_cluster_*     : Parameters starting with src_cluster contain source cluster details from where user wants to migrate volume
	 - dest_cluster*     : Parameters starting with dest_cluster contain destination cluster details to where volume will be migrated
	 - brocade_switch_*  : Parameters starting with brocade_switch contain brocade switch details 
	 - application_host_*: Parameters starting with application_host contain application host details which is performing read/write of data
         - volume_details    : It consists of volume to be migrated with its source and destination name with host it is attached to
  2. initiate_migration_for_given_volume:
     - This playbook initiates the migration, creates fc host with the same name as source cluster and adds it to the default portset.
	 - Most importantly, it also starts data copy from source cluster to destination cluster
  Note:
     User should not run playbook create_zone_map_volume_and_rescan until relationship is in consistent_syncronized state     	 
  3. create_zone_map_volume_and_rescan
     - Execute this playbook once the relationship created by above playbook is in consistent_syncronized state.
     - This playbook fetches the list of SCSI_HOST WWPN's associated with given fcioportid from specV destination cluster.
     - Creates zone with the name given and add specV ports fetched and host WWPN's given.
     - Maps the volume to the Host and starts scsi rescan on the host.
     - Switch replication direction of a migration relationship once host is mapped.
     - Again rescan the volume on the host to get the updated path details.
     - Delete source volume and migration relationship which was created.
     - Again rescan the volume on the host to get the reduced paths.
  
 Authors: Ajinkya Nanavati (ananava1@in.ibm.com)
          Mohit Chitlange  (mochitla@in.ibm.com)

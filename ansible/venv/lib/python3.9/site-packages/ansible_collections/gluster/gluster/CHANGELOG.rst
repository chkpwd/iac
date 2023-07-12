========================================
Gluster Ansible Collection Release Notes
========================================

.. contents:: Topics


v1.0.2
======

Major Changes
-------------

- enable client.ssl,server.ssl before starting the gluster volume (https://github.com/gluster/gluster-ansible-collection/pull/19)

v1.0.1
======

v1.0.0
======

Major Changes
-------------

- geo_rep - Added the independent module of geo rep with other gluster modules (https://github.com/gluster/gluster-ansible-collection/pull/2).

New Modules
-----------

- gluster.gluster.geo_rep - Manage geo-replication sessions
- gluster.gluster.gluster_heal_info - Gather facts about either self-heal or rebalance status
- gluster.gluster.gluster_peer - Attach/Detach peers to/from the cluster
- gluster.gluster.gluster_volume - Manage GlusterFS volumes

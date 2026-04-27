"""
Placeholder for future volsync helpers.

Phase 0 keeps the existing `core/volsync/components` Kustomize component as the
source of truth for the ReplicationSource/ReplicationDestination pair. Apps
still reference it from their flux-kustomization.yml.

If/when we migrate apps off the Kustomize component and into KCL-rendered
volsync resources, schemas live here. For now this file exists to reserve
the import path.
"""

schema VolsyncRef:
    """Identifier used to wire an app's PVC to its ReplicationDestination."""
    name: str
    capacity: str
    puid: str
    pgid: str

"""
Render an `App` as raw Kubernetes resources (no Helm).

Produces: StatefulSet + Service + HTTPRoute + (PVC via volumeClaimTemplate).
Used by tautulli in Phase 2 as the side-by-side comparison against the
HelmRelease path (helm_release.k).

NOT YET IMPLEMENTED — this file is a placeholder so the import path exists.
Implementation lands in Phase 2 alongside tautulli's app source.
"""

import .app as a

renderRawWorkload = lambda app: a.App -> [{str:any}] {
    # TODO(phase-2): emit StatefulSet + Service + HTTPRoute + (optional) ExternalSecret refs.
    # Until then, return an empty list so the import is valid.
    []
}

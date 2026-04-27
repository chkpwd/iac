"""
Flux Kustomization renderer.

Wraps the boilerplate-heavy `flux-kustomization.yml` that every app currently
hand-writes. Renders to `kustomize.toolkit.fluxcd.io/v1` Kustomization with
the per-cluster defaults (sourceRef chkpwd-ops, prune, wait=false, interval).

The `apps` parent Kustomization in flux/cluster.yml supplies sopsDecryption,
default timings, HelmRelease defaults, and PostgresCluster patches via its
own `patches:`. Per-app Kustomizations only need their per-app fields:
namespace, components, postBuild substitutes.

# Path constants

Components and other in-repo references are resolved by the kustomize
controller relative to the Flux Kustomization `path` (which always
points at `kubernetes/kcl/apps/<name>/resources/`). Use the constants
below instead of hand-counting `../`:

    components = [
        "${core()}/volsync/components"
        "${core()}/keda-operator/_components/nfs/"
    ]

If the generated-output layout ever moves, only this file changes.
"""

# Relative path from kubernetes/kcl/apps/<name>/resources/ to kubernetes/core/.
# 4 levels up:  resources -> <name> -> apps -> kcl -> kubernetes  then  /core
# Exposed as a zero-arg lambda because KCL only re-exports schemas and
# lambdas across `import` boundaries — bare constants are not visible.
core = lambda -> str { "../../../../core" }

schema FluxKustomization:
    """One Flux Kustomization for one app.

    `name` doubles as the postBuild `${APP}` substitution and the
    commonMetadata label `app.kubernetes.io/name`.

    `path` defaults to the canonical generated-output location
    `./kubernetes/kcl/apps/<name>/resources` and rarely needs override.
    """
    name: str
    namespace: str                          # = targetNamespace
    path?: str                              # default: ./kubernetes/kcl/apps/<name>/resources
    components?: [str] = []                 # repo-relative paths
    postBuildSubstitute?: {str:str} = {}    # extra vars beyond APP
    dependsOn?: [str] = []                  # other Kustomization names

    # Defaults baked in (rarely overridden):
    interval: str = "30m"
    sourceName: str = "chkpwd-ops"
    sourceNamespace: str = "flux-system"

renderFluxKustomization = lambda fks: FluxKustomization -> {str:any} {
    _substitute = {"APP" = fks.name} | (fks.postBuildSubstitute or {})
    _path = fks.path or "./kubernetes/kcl/apps/${fks.name}/resources"

    _spec = {
        "targetNamespace" = fks.namespace
        "path" = _path
        "commonMetadata" = {
            "labels" = {"app.kubernetes.io/name" = fks.name}
        }
        "prune" = True
        "wait" = False
        "interval" = fks.interval
        "sourceRef" = {
            "kind" = "GitRepository"
            "name" = fks.sourceName
            "namespace" = fks.sourceNamespace
        }
        "postBuild" = {"substitute" = _substitute}
    } | ({"components" = fks.components} if fks.components else {}) \
      | ({"dependsOn" = [{"name" = n} for n in fks.dependsOn]} if fks.dependsOn else {})

    {
        "apiVersion" = "kustomize.toolkit.fluxcd.io/v1"
        "kind" = "Kustomization"
        "metadata" = {
            "name" = fks.name
            "namespace" = "flux-system"
        }
        "spec" = _spec
    }
}

# Helper: render the inner kustomize.config Kustomization that lives at
# <app>/dist/kustomization.yml. Resources list is fixed.
renderInnerKustomization = lambda resources: [str] -> {str:any} {
    {
        "apiVersion" = "kustomize.config.k8s.io/v1beta1"
        "kind" = "Kustomization"
        "resources" = resources
    }
}

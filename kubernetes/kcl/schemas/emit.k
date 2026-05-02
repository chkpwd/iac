"""
emit.app — single helper that turns per-app KCL config into the standard
3-file output bundle:

    kubernetes/kcl/apps/<name>/resources/manifests.yml
    kubernetes/kcl/apps/<name>/resources/kustomization.yml
    kubernetes/kcl/apps/<name>/resources/flux-kustomization.yml

Returns a list of `{__file, doc}` records that the Taskfile splitter
routes to the correct files. Caller wraps with `manifests.yaml_stream`:

    import schemas.emit as emit
    import manifests

    manifests.yaml_stream(emit.app(
        name = "bazarr",
        helmRelease = _app,
        externalSecret = _externalSecret,
        fluxKustomization = _fluxKustomization,
    ))

`name` drives the path; everything else is optional. Apps that need
extra raw resources can pass them via `extras` (each becomes another
doc in manifests.yml).
"""

import schemas.helm_release as hr
import schemas.external_secret as es
import schemas.flux_kustomization as fk

# Render a fully-bundled app to the standard output layout.
#
# Returns: [{__file: str, doc: any}] suitable for manifests.yaml_stream.
app = lambda name: str, helmRelease: any = None, externalSecret: any = None, fluxKustomization: any = None, extras: [any] = [] -> [{str:any}] {
    _base = "kubernetes/kcl/apps/${name}/resources"
    _manifestsFile = "${_base}/manifests.yml"
    _kustFile      = "${_base}/kustomization.yml"
    _fluxFile      = "${_base}/flux-kustomization.yml"

    # Order: HelmRelease, ExternalSecret, then any extras — all into manifests.yml.
    _manifestsDocs = ([{"__file" = _manifestsFile, "doc" = hr.renderHelmRelease(helmRelease)}] if helmRelease else []) \
                   + ([{"__file" = _manifestsFile, "doc" = es.renderExternalSecret(externalSecret)}] if externalSecret else []) \
                   + [{"__file" = _manifestsFile, "doc" = e} for e in extras]

    # Inner kustomization always lists exactly manifests.yml.
    _kustDoc = {
        "__file" = _kustFile
        "doc"    = fk.renderInnerKustomization(["manifests.yml"])
    }

    # Flux Kustomization (parent, lives one dir up — read by apps-kcl aggregator).
    _fluxDocs = [{"__file" = _fluxFile, "doc" = fk.renderFluxKustomization(fluxKustomization)}] if fluxKustomization else []

    _manifestsDocs + [_kustDoc] + _fluxDocs
}

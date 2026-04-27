"""
Render an `App` as a Flux HelmRelease consuming the bjw-s app-template chart.

Produces a single HelmRelease dict.

Use via:

    import schemas.helm_release as hr
    helmrelease = hr.renderHelmRelease(myApp)

The renderer is a lambda; the caller binds the result to a top-level name.
For a clean YAML output without a variable wrapper, output via
`yaml.encode(helmrelease)` or use `kcl run -o ... -D` semantics.
"""

import .app as a

# Pinned chart version. Bump here for every app in one place.
_chartVersion = "4.6.2"
_chartName = "app-template"
_repoName = "bjw-s-labs"
_repoNamespace = "flux-system"


# Strip None values from a dict (one level deep). KCL emits None as `null`
# in YAML, which we don't want for omitted optional fields.
_clean = lambda d: {str:any} -> {str:any} {
    {k: v for k, v in d if v != None and v != {} and v != []}
}

renderHelmRelease = lambda app: a.App -> {str:any} {
    _ctlName = app.name
    _annotations = {"reloader.stakater.com/auto" = "true"} if app.reloader else None

    _envBlock = app.env or {}
    _envFromSecretBlock = {
        k: {"valueFrom" = {"secretKeyRef" = {"name" = v.secret, "key" = v.key}}}
        for k, v in app.envFromSecret or {}
    }
    _allEnv = _envBlock | _envFromSecretBlock

    _probeSpec = {
        "enabled" = True
        "custom" = True
        "spec" = {
            "httpGet" = {"path" = app.probe.path, "port" = app.port}
            "initialDelaySeconds" = app.probe.initialDelaySeconds
            "periodSeconds" = app.probe.periodSeconds
            "timeoutSeconds" = app.probe.timeoutSeconds
            "failureThreshold" = app.probe.failureThreshold
        }
    } if app.probe else None

    _probesBlock = {
        "liveness" = _probeSpec
        "readiness" = _probeSpec
        "startup" = {"enabled" = False}
    } if _probeSpec else None

    _container = _clean({
        "image" = {
            "repository" = app.image.repository
            "tag" = app.image.tag
            "pullPolicy" = app.image.pullPolicy
        }
        "env" = _allEnv if _allEnv else None
        "command" = app.command
        "args" = app.args
        "probes" = _probesBlock
        "securityContext" = {
            "allowPrivilegeEscalation" = False
            "capabilities" = {"drop" = ["ALL"]}
        }
        "resources" = _clean({
            "requests" = app.resources.requests
            "limits" = app.resources.limits
        }) if app.resources else None
    })

    _volumeClaimTemplates = [{
        "name" = app.persistence.name
        "accessMode" = app.persistence.accessMode
        "size" = app.persistence.size
        "storageClass" = app.persistence.storageClass
        "dataSourceRef" = {
            "kind" = "ReplicationDestination"
            "apiGroup" = "volsync.backube"
            "name" = app.persistence.replicationDestination or app.name
        }
        "globalMounts" = [{"path" = app.persistence.mountPath}]
    }] if app.persistence else None

    _podSec = {
        "securityContext" = {
            "runAsUser" = app.securityContext.runAsUser
            "runAsGroup" = app.securityContext.runAsGroup
            "fsGroup" = app.securityContext.fsGroup
            "fsGroupChangePolicy" = app.securityContext.fsGroupChangePolicy
        }
    } if app.securityContext else None

    _persistence = {
        "data" = {
            "enabled" = True
            "type" = "nfs"
            "server" = app.nfs.server
            "path" = app.nfs.path
        }
    } if app.nfs else None

    _route = {
        "private" = {
            "kind" = "HTTPRoute"
            "hostnames" = [app.route.hostname]
            "parentRefs" = [{
                "name" = app.route.parentName
                "namespace" = app.route.parentNamespace
                "sectionName" = app.route.parentSectionName
            }]
        }
    } if app.route else None

    _controller = _clean({
        "type" = app.controllerType
        "annotations" = _annotations
        "replicas" = 1
        "statefulset" = {"volumeClaimTemplates" = _volumeClaimTemplates} if _volumeClaimTemplates else None
        "pod" = _podSec
        "containers" = {"app" = _container}
    })

    _values = _clean({
        "controllers" = {"${_ctlName}" = _controller}
        "service" = {
            "app" = {
                "controller" = _ctlName
                "ports" = {"http" = {"port" = app.port}}
            }
        }
        "route" = _route
        "persistence" = _persistence
    })

    {
        "apiVersion" = "helm.toolkit.fluxcd.io/v2"
        "kind" = "HelmRelease"
        "metadata" = {"name" = app.name}
        "spec" = {
            "interval" = "1h"
            "chart" = {
                "spec" = {
                    "chart" = _chartName
                    "version" = _chartVersion
                    "interval" = "30m"
                    "sourceRef" = {
                        "kind" = "HelmRepository"
                        "name" = _repoName
                        "namespace" = _repoNamespace
                    }
                }
            }
            "values" = _values
        }
    }
}

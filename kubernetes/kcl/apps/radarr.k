import schemas.app as a
import schemas.external_secret as es
import schemas.flux_kustomization as fk
import schemas.emit as emit
import manifests

_app = a.App {
    name = "radarr"
    namespace = "media"
    image = a.Image {
        repository = "ghcr.io/home-operations/radarr"
        tag = "6.2.0.10390"
    }
    port = 7878
    # Same as sonarr — runs as NAS media UID/GID for direct NFS access.
    securityContext = a.SecurityContext {
        runAsUser = 1026
        runAsGroup = 100
        fsGroup = 100
    }
    resources = a.Resources {
        requests = a.qty(cpu="100m")
        limits   = a.qty(memory="4Gi")
    }
    probe = a.Probe {
        path = "/ping"
        port = 7878
    }
    env = {
        "TZ" = "America/New_York"
        "RADARR__INSTANCE_NAME" = "radarr"
        "RADARR__SERVER__PORT" = 7878
        "RADARR__AUTH__METHOD" = "External"
        "RADARR__APP__THEME" = "dark"
        "RADARR__LOG__LEVEL" = "info"
    }
    envFromSecret = {
        "RADARR__AUTH__APIKEY" = a.EnvSecretRef {
            secret = "radarr"
            key = "RADARR_API_KEY"
        }
    }
    persistence = a.VolsyncPVC {
        size = "\${VOLSYNC_CAPACITY}"
    }
    nfs = a.PersistenceNFS {
        server = "nas-srv-01.chkpwd.com"
        path = "/volume1/vault-01/media"
    }
    route = a.Route {
        hostname = "radarr.chkpwd.com"
    }
}

_externalSecret = es.ExternalSecretSpec {
    name = "radarr"
    bitwardenKey = "infra-media-secrets"
    template = {
        "RADARR_API_KEY" = "radarr_api_key"
    }
}

_fluxKustomization = fk.FluxKustomization {
    name = "radarr"
    namespace = "media"
    components = [
        "${fk.core()}/volsync/components"
        "${fk.core()}/keda-operator/_components/nfs/"
    ]
    postBuildSubstitute = {
        "CLAIM" = "config-radarr-0"
        "VOLSYNC_PUID" = "1026"
        "VOLSYNC_PGID" = "100"
        "VOLSYNC_CAPACITY" = "2Gi"
    }
}

manifests.yaml_stream(emit.app(
    name              = "radarr"
    helmRelease       = _app
    externalSecret    = _externalSecret
    fluxKustomization = _fluxKustomization
))

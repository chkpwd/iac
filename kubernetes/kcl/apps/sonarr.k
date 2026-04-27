import schemas.app as a
import schemas.external_secret as es
import schemas.flux_kustomization as fk
import schemas.emit as emit
import manifests

_app = a.App {
    name = "sonarr"
    namespace = "media"
    image = a.Image {
        repository = "ghcr.io/home-operations/sonarr"
        tag = "4.0.17.2953"
    }
    port = 8989
    resources = a.Resources {
        requests = a.qty(cpu="50m")
        limits   = a.qty(memory="3Gi")
    }
    probe = a.Probe {
        path = "/ping"
        port = 8989
    }
    env = {
        "TZ" = "America/New_York"
        "SONARR__APP__INSTANCENAME" = "Sonarr"
        "SONARR__AUTH__METHOD" = "External"
        "SONARR__AUTH__REQUIRED" = "DisabledForLocalAddresses"
        "SONARR__APP__THEME" = "dark"
        "SONARR__LOG__LEVEL" = "info"
        "SONARR__SERVER__PORT" = 8989
        "SONARR__UPDATE__BRANCH" = "develop"
    }
    envFromSecret = {
        "SONARR__AUTH__APIKEY" = a.EnvSecretRef {
            secret = "sonarr"
            key = "SONARR_API_KEY"
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
        hostname = "sonarr.chkpwd.com"
    }
}

_externalSecret = es.ExternalSecretSpec {
    name = "sonarr"
    bitwardenKey = "infra-media-secrets"
    template = {
        "SONARR_API_KEY" = "sonarr_api_key"
    }
}

_fluxKustomization = fk.FluxKustomization {
    name = "sonarr"
    namespace = "media"
    components = [
        "${fk.core()}/volsync/components"
        "${fk.core()}/keda-operator/_components/nfs/"
    ]
    postBuildSubstitute = {
        "CLAIM" = "config-sonarr-0"
        "VOLSYNC_PUID" = "1026"
        "VOLSYNC_PGID" = "100"
        "VOLSYNC_CAPACITY" = "3Gi"
    }
}

manifests.yaml_stream(emit.app(
    name              = "sonarr"
    helmRelease       = _app
    externalSecret    = _externalSecret
    fluxKustomization = _fluxKustomization
))

import schemas.app as a
import schemas.external_secret as es
import schemas.flux_kustomization as fk
import schemas.emit as emit
import manifests

_app = a.App {
    name = "bazarr"
    namespace = "media"
    image = a.Image {
        repository = "ghcr.io/home-operations/bazarr"
        tag = "1.5.6"
    }
    port = 6767
    resources = a.Resources {
        requests = a.qty(cpu="15m", memory="256Mi")
        limits   = a.qty(memory="512Mi")
    }
    probe = a.Probe {
        path = "/api"
        port = 6767
    }
    env = {
        "TZ" = "America/New_York"
        "BAZARR__INSTANCE_NAME" = "bazarr"
        "BAZARR__SERVER__PORT" = 6767
        "BAZARR__AUTH__METHOD" = "External"
        "BAZARR__AUTH__REQUIRED" = "DisabledForLocalAddresses"
        "BAZARR__LOG__LEVEL" = "info"
    }
    envFromSecret = {
        "BAZARR__AUTH__APIKEY" = a.EnvSecretRef {
            secret = "bazarr"
            key = "BAZARR_API_KEY"
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
        hostname = "bazarr.chkpwd.com"
    }
}

_externalSecret = es.ExternalSecretSpec {
    name = "bazarr"
    bitwardenKey = "infra-media-secrets"
    template = {
        "BAZARR_API_KEY" = "bazarr_api_key"
    }
}

_fluxKustomization = fk.FluxKustomization {
    name = "bazarr"
    namespace = "media"
    components = [
        "${fk.core()}/volsync/components"
        "${fk.core()}/keda-operator/_components/nfs/"
    ]
    postBuildSubstitute = {
        "CLAIM" = "config-bazarr-0"
        "VOLSYNC_PUID" = "1999"
        "VOLSYNC_PGID" = "1999"
        "VOLSYNC_CAPACITY" = "500Mi"
    }
}

manifests.yaml_stream(emit.app(
    name              = "bazarr"
    helmRelease       = _app
    externalSecret    = _externalSecret
    fluxKustomization = _fluxKustomization
))

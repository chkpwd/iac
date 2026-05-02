import schemas.app as a
import schemas.external_secret as es
import schemas.flux_kustomization as fk
import schemas.emit as emit
import manifests

_app = a.App {
    name = "prowlarr"
    namespace = "media"
    image = a.Image {
        repository = "ghcr.io/home-operations/prowlarr"
        tag = "2.3.6.5351"
    }
    port = 9696
    resources = a.Resources {
        requests = a.qty(cpu="10m", memory="131Mi")
        limits   = a.qty(memory="200Mi")
    }
    probe = a.Probe {
        path = "/ping"
        port = 9696
    }
    env = {
        "TZ" = "America/New_York"
        "PROWLARR__INSTANCE_NAME" = "Prowlarr"
        "PROWLARR__SERVER__PORT" = 9696
        "PROWLARR__AUTH__METHOD" = "External"
        "PROWLARR__AUTH__REQUIRED" = "DisabledForLocalAddresses"
        "PROWLARR__APP__THEME" = "dark"
        "PROWLARR__LOG__LEVEL" = "info"
    }
    envFromSecret = {
        "PROWLARR__AUTH__APIKEY" = a.EnvSecretRef {
            secret = "prowlarr"
            key = "PROWLARR_API_KEY"
        }
    }
    persistence = a.VolsyncPVC {
        size = "\${VOLSYNC_CAPACITY}"
    }
    # No NFS — prowlarr is an indexer, no media mount.
    route = a.Route {
        hostname = "prowlarr.chkpwd.com"
    }
}

_externalSecret = es.ExternalSecretSpec {
    name = "prowlarr"
    bitwardenKey = "infra-media-secrets"
    template = {
        "PROWLARR_API_KEY" = "prowlarr_api_key"
    }
}

_fluxKustomization = fk.FluxKustomization {
    name = "prowlarr"
    namespace = "media"
    components = [
        "${fk.core()}/volsync/components"
    ]
    postBuildSubstitute = {
        "CLAIM" = "config-prowlarr-0"
        "VOLSYNC_PUID" = "1999"
        "VOLSYNC_PGID" = "1999"
        "VOLSYNC_CAPACITY" = "700Mi"
    }
}

manifests.yaml_stream(emit.app(
    name              = "prowlarr"
    helmRelease       = _app
    externalSecret    = _externalSecret
    fluxKustomization = _fluxKustomization
))

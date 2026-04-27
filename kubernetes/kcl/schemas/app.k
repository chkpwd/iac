schema Image:
    repository: str
    tag: str
    pullPolicy: str = "IfNotPresent"

schema Resources:
    """Container resource requests and limits."""
    requests?: Resources
    limits?: Resources
    cpu?: str
    memory?: str

# Terse constructor for one side of a Resources block.
qty = lambda cpu: str = "", memory: str = "" -> Resources {
    Resources {
        cpu = cpu if cpu else Undefined
        memory = memory if memory else Undefined
    }
}

schema Probe:
    """HTTP probe spec — path + port only, sensible defaults applied by renderer."""
    path: str
    port: int
    initialDelaySeconds: int = 0
    periodSeconds: int = 10
    timeoutSeconds: int = 1
    failureThreshold: int = 3

schema SecurityContext:
    """Pod-level security context.

    Defaults to UID/GID 1999 — the standard non-root identity used by
    every app in this repo. Apps with different ownership requirements
    (e.g. ones that interop with NFS shares owned by other UIDs)
    override the relevant field.
    """
    runAsUser: int = 1999
    runAsGroup: int = 1999
    fsGroup: int = 1999
    fsGroupChangePolicy: str = "OnRootMismatch"

schema EnvSecretRef:
    secret: str
    key: str

schema PersistenceNFS:
    server: str
    path: str
    mountPath: str = "/data"

schema VolsyncPVC:
    """Per-app PVC backed by volsync ReplicationDestination dataSourceRef."""
    name: str = "config"
    size: str
    storageClass: str = "ceph-block"
    accessMode: str = "ReadWriteOnce"
    mountPath: str = "/config"
    # Defaults to app name; override only if needed.
    replicationDestination?: str

schema Route:
    """Gateway API HTTPRoute pointing at a parent Gateway."""
    hostname: str
    parentName: str = "private"
    parentNamespace: str = "networking"
    parentSectionName: str = "https"

schema App:
    """
    Declarative spec for one application.

    Renderers (helm_release.k / raw_workload.k) turn this into Kubernetes
    resources. Keep this schema renderer-agnostic.
    """
    name: str
    namespace: str = "media"
    image: Image
    port: int
    controllerType: str = "statefulset"

    env?: {str:str|int}
    envFromSecret?: {str:EnvSecretRef}
    command?: [str]
    args?: [str]

    resources?: Resources
    probe?: Probe
    # Defaults to SecurityContext {} (UID/GID 1999). Override only if
    # the app needs different IDs.
    securityContext: SecurityContext = SecurityContext {}

    persistence?: VolsyncPVC
    nfs?: PersistenceNFS
    route?: Route

    # Reloader annotation toggle — true by default (matches existing manifests).
    reloader: bool = True

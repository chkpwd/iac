# chkpwd-ops KCL module

Shared KCL schemas for generating Flux-managed app manifests in this repo.

## Layout

```
kcl/
├── kcl.mod                 # module manifest
├── schemas/
│   ├── app.k               # base App schema definitions
│   ├── helm_release.k      # bjw-s app-template HelmRelease wrapper
│   ├── external_secret.k   # ExternalSecret wrapper
│   ├── volsync.k           # volsync PVC dataSourceRef helper
│   └── raw_workload.k      # raw StatefulSet+Service+HTTPRoute (no Helm)
├── apps/
│   ├── bazarr.k            # per-app source
│   └── radarr.k
└── examples/               # worked examples (not consumed by apps)
```

## Conventions

- One `<name>.k` per application, located at `apps/<name>.k`.
- Generated YAML lives at `apps/<name>/*.yml` and is **never edited by hand**.
- Regenerate with `task kcl:build APP=<name>` or `task kcl:build` for all apps.
- Build OCI payload with `task kcl:artifact`.
- CI builds and publishes the rendered OCI artifact.

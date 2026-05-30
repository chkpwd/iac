# Migration Plan: Helm/Kustomize → Kro with RGDs

## Context

**Current state:**

- 30 apps in `apps/` using Flux Kustomization + Flux HelmRelease (bjw-s `app-template` chart v5.0.0)
- 34 core components (cert-manager, cilium, prometheus, volsync, external-secrets, etc.)
- KCL code generation (kcl/) produces YAML that gets committed to git → Flux reconciles from git
- Problem: KCL needs somewhere to store rendered YAML (separate git branch or Flux GitRepository). User wants to talk directly to the Kubernetes API instead.

**Target state:**

- Kro RGDs applied directly to cluster (via `kubectl apply` or Flux)
- Kro controller talks directly to kube-apiserver to reconcile child resources
- No intermediate YAML storage — instance CRs ARE the API
- Flux still drives top-level Kustomization, but sources point to Kro instance YAML instead of HelmRelease YAML

## Kro Documentation Coverage

All Kro documentation pages were read and analyzed:

- Overview, RGD Overview, Quick Start, Installation
- Schema Definition (SimpleSchema syntax, custom types, printer columns)
- Resource Definitions: Basics, Conditionals, Readiness, Collections, External References
- CEL Expressions (full syntax, libraries, string templating, escape syntax)
- Graph Inference (dependency ordering, DAG patterns)
- Static Analysis (8-stage validation pipeline, type checking)
- Instances (labels, ownership, ApplySet, owner references, debugging)
- Access Control (unrestricted vs aggregation mode)
- Feature Gates, Controller Tuning, Graph Revisions, Controller Metrics
- Single Resource RGD, Multi Resource RGD, RGD Chaining
- FAQ (ArgoCD integration, breaking changes)
- Examples: Web App, Web App w/ Ingress, Optionals
- API Reference: SimpleSchema spec, CRD specs, GraphRevision spec

## Why Kro Solves the KCL Problem

|                    | KCL                                   | Kro                                                              |
| ------------------ | ------------------------------------- | ---------------------------------------------------------------- |
| Where YAML lives   | Committed to git (or separate branch) | Never stored — Kro creates resources directly                    |
| Flux dependency    | Flux pulls git → syncs HelmReleases   | Flux pulls git → creates RGD instances → Kro reconciles children |
| Change propagation | Re-run KCL, commit, push              | Update instance spec, Kro reconciles                             |
| Tooling            | KCL CLI + CI pipeline                 | Just `kubectl apply` (or Flux)                                   |

## Kro Features Applicable to This Migration

### 1. SimpleSchema (Schema Definition)

Maps directly from `app.k` KCL schema:

- **Basic types**: `string`, `integer`, `boolean`, `float`
- **Structures**: nested objects for `image`, `resources`, `probe`, `securityContext`, `persistence`, `nfs`, `route`
- **Collections**: `map[string]string` for `env`, `envFromSecret`
- **Custom types**: define `ContainerResources`, `ProbeSpec`, `PersistenceSpec` in `types:` block for reuse across RGDs
- **Validation markers**: `required`, `default`, `minimum`, `maximum`, `enum`, `pattern`, `immutable`, `description`
- **Printer columns**: `additionalPrinterColumns` on the schema so `kubectl get mediaapp` shows name, replicas, image, ready state

### 2. includeWhen (Conditionals)

The primary replacement for kustomize `components/` and `patchesJson6902`:

- **Route/HTTPRoute**: create only when `route.enabled == true`
- **Volsync PVC**: create only when `persistence.size` is set (persistence is optional)
- **NFS volume**: include only when `nfs.server` is provided
- **ExternalSecret**: include only when `secretRef` keys are provided
- All-or-nothing per collection — cannot filter individual items; use `filter()` in `forEach` expression if per-item filtering needed

### 3. readyWhen (Readiness)

Controls sequencing without toggling resource existence:

- **Deployment readiness**: `${deployment.status.availableReplicas > 0}` — app pod must be running before HTTPRoute backend is ready
- **Service readiness**: `${service.spec.clusterIP != ""}` — service must have a ClusterIP before HTTPRoute can route
- **ExternalSecret readiness**: use when referencing secrets in `envFrom` — wait for secret to exist
- **NFS mount readiness**: use optional operator `${nfsConfig.data.?NFS_SERVER}` to safely wait
- **Per-collection readiness**: use `each` keyword: `${each.status.phase == 'Running'}`

### 4. forEach (Collections)

For generating multiple related resources from a single definition:

- **Multiple containers**: if any app ever needs sidecars, `forEach: [container: ${schema.spec.sidecars}]` creates one Pod per sidecar
- **Multiple ports**: `forEach: [port: ${schema.spec.ports}]` creates one `ServicePort` per port
- **Multiple env vars from secret**: iterate over `envFromSecret` map keys to create multiple secret key refs
- **Cartesian product**: `forEach: [region: ${schema.spec.regions}, tier: ${schema.spec.tiers}]` creates all combinations
- **Constraints**: max 1000 items per collection (configurable), max 10 dimensions, collection must include all iterator dimensions in resource name for uniqueness
- **Empty collections are ready**: `persistence.size` can be unset → no volumeClaimTemplate created → collection is ready

### 5. externalRef (External References)

Reference existing cluster resources Kro doesn't manage:

- **BitwardenSecretsManager ClusterSecretStore**: reference the existing `ClusterSecretStore` (`bitwarden-secrets-manager`) so ExternalSecretRGD can use it without recreating it
- **NFS server**: cannot use `externalRef` for NFS (no CRD) — instead express as direct volume mounts in Deployment template
- **Shared ConfigMaps**: reference platform-wide `ConfigMap` objects (e.g., timezone configs) as externalRefs
- **Reactive watches**: when the external resource changes, kro triggers re-reconciliation automatically
- **External collections**: use `selector` instead of `name` to reference all ConfigMaps/Secrets matching a label across namespaces
- **CEL expressions in selectors**: `values: ["${schema.spec.teamName}"]` filters external refs per-instance
- **Optional operator**: always use `?` when accessing externalRef data fields: `${secret.data.?API_KEY.orValue("")}`

### 6. CEL Expressions

The primary wiring mechanism:

- **Schema references**: `${schema.spec.name}`, `${schema.spec.image.tag}`
- **Resource references**: `${deployment.spec.template.spec.containers[0].image}`
- **Status references**: `${deployment.status.availableReplicas}`, `${service.status.loadBalancer.ingress[0].hostname}`
- **String concatenation**: `"${schema.metadata.namespace}-${schema.spec.name}"` for names
- **Ternary**: `image: ${schema.spec.env == "prod" ? "nginx:stable" : "nginx:latest"}`
- **orValue()**: `${schema.spec.?optionalField.orValue("default")}` for optional fields
- **String conversion**: `value: ${string(schema.spec.port)}` when integer must be string
- **CEL libraries available**:
  - `lists.range(n)`, `lists.setAtIndex`, `lists.insertAtIndex`, `lists.removeAtIndex`
  - `hash.fnv64a`, `hash.sha256`, `hash.md5`
  - `base64.encode`, `base64.decode`
  - `merge()` for combining maps
  - `sortBy()`, `filter()`, `map()`, `all()`, `exists()`, `size()`
- **Escaping `${VAR}`**: use `${"${VAR}"}` for literal shell-style variable output

### 7. Static Analysis (8-stage validation)

kro validates at RGD creation time, catching errors before instances run:

- Stage 1: Schema validation (SimpleSchema parsing)
- Stage 2: Status schema inference (CEL → inferred types)
- Stage 3: Resource naming (camelCase required, no hyphens)
- Stage 4: Resource template validation (OpenAPI schema fetch from API server)
- Stage 5: CEL AST parsing and dependency graph building
- Stage 6: Expression type checking (output type vs target field type)
- Stage 7: `readyWhen`/`includeWhen` validation (must return boolean)
- Stage 8: RGD activation (CRD registration, controller startup)
- **Breaking change detection**: schema changes (removing fields, type changes, new required fields without defaults) are blocked by default; use `kro.run/allow-breaking-changes: "true"` annotation to override
- **Structural compatibility**: map ↔ struct conversion supported; subset semantics for structs (extra fields in output cause error)

### 8. Graph Revisions

Every RGD spec change creates an immutable GraphRevision:

- **Retention**: default 5 revisions kept per RGD (configurable via `config.rgd.maxGraphRevisions`)
- **Debugging**: `kubectl get gr` shows revision history; `kubectl describe gr <name>` shows compilation errors
- **No fallback**: failed revisions block instances — no automatic rollback to older revision
- **Orphan deletion**: `kubectl delete rgd <name> --cascade=orphan` preserves revisions for RGD recreation
- **Spec hash deduplication**: cosmetic changes (whitespace, key reordering) ignored
- **Topological order**: `status.topologicalOrder` shows computed resource creation order

### 9. Instance Labels and Ownership

kro applies extensive metadata to managed resources:

- **Labels on child resources**: `app.kubernetes.io/managed-by: kro`, `kro.run/instance-id`, `kro.run/instance-name`, `kro.run/node-id`
- **Collection labels**: `kro.run/collection-index`, `kro.run/collection-size`
- **ApplySet**: uses `applyset.kubernetes.io/part-of` label for pruning orphaned resources (not owner references)
- **Manual owner references**: can be added to resource templates for ArgoCD compatibility (see FAQ), but has limitations (cross-namespace, out-of-order deletion)
- **Suspend reconciliation**: `kro.run/reconcile: suspended` annotation on instance pauses active reconciliation

### 10. RGD Chaining

Use Kro-generated CRs as resources in other RGDs:

- **Tier-1 → Tier-2 composition**: MediaAppRGD creates `ExternalSecret` instance → the ExternalSecretRGD's controller reconciles it
- **Status propagation**: inner RGD status fields (endpoint, ready, connection string) surface to outer RGD status
- **Wait for readiness**: outer RGD automatically waits for inner instance's `Ready` condition before proceeding
- **Deletion order**: outer instance deleted → cascades to inner instances → inner controllers delete their children

### 11. Access Control

- **aggregation mode** (recommended): Kro gets minimal permissions; needs explicit ClusterRole with `rbac.kro.run/aggregate-to-controller: "true"` label for each resource type it manages
  - Will need ClusterRole for: Deployment, Service, ConfigMap, Secret, HTTPRoute, ExternalSecret, Ingress, StatefulSet, VolumeClaimTemplate, ReplicationSource, ServiceAccount, RoleBinding
- **unrestricted mode**: grants full cluster admin — not recommended for production

### 12. Controller Metrics

Rich Prometheus metrics for monitoring:

- `dynamic_controller_reconcile_total`, `dynamic_controller_reconcile_duration_seconds`
- `dynamic_controller_queue_length` (workqueue depth)
- `dynamic_controller_informer_events_total`
- `rgd_graph_build_total`, `rgd_graph_build_errors_total`
- `graph_revision_compile_total`, `graph_revision_compile_duration_seconds`
- `instance_reconcile_total`, `instance_reconcile_errors_total`
- Prometheus Operator `ServiceMonitor` available via Helm values
- Metrics endpoint on port 8078 (configurable)

### 13. Controller Tuning

Helm-configurable for your cluster size:

- `config.resourceGraphDefinitionConcurrentReconciles`: RGD reconciler concurrency
- `config.dynamicControllerConcurrentReconciles`: instance reconciler concurrency (default 1)
- `config.dynamicControllerDefaultResyncPeriod`: periodic full resync (default 10h)
- `config.clientQps` / `config.clientBurst`: API server request throttling
- `config.instance.requeueInterval`: delay when waiting for readiness (default 3s)
- Rate limiter: exponential backoff + bucket rate limiter via flags

### 14. ArgoCD Integration (from FAQ)

If using ArgoCD (not Flux), add tracking annotation to resource templates:

```yaml
metadata:
  ownerReferences:
    - apiVersion: kro.run/v1alpha1
      kind: ${schema.kind}
      name: ${schema.metadata.name}
      uid: ${schema.metadata.uid}
  annotations:
    argocd.argoproj.io/tracking-id: ${schema.metadata.?annotations["argocd.argoproj.io/tracking-id"]}
```

Note: limitations apply — cross-namespace and cluster-scoped resources have constraints.

### 15. Additional Printer Columns

On the schema, define custom kubectl columns:

```yaml
additionalPrinterColumns:
  - jsonPath: .spec.replicas
    name: Replicas
    type: integer
  - jsonPath: .status.availableReplicas
    name: Available
    type: integer
  - jsonPath: .spec.image.tag
    name: Tag
    type: string
  - jsonPath: .metadata.creationTimestamp
    name: Age
    type: date
```

So `kubectl get mediaapp` shows a clean table without needing `-o yaml`.

### 16. Structured vs Unstructured Types

- **Prefer structured types** over `object` — enables full type checking and validation
- **`object` type** disables field validation; forwards values as-is — use only when schema is truly unknown in advance
- **Custom types in `types:` block**: reusable type definitions that Kro expands inline in the generated CRD

## RGD Design Decisions

### Architecture: Multi-layer hierarchy

Two tiers of RGDs map directly to the existing `core` vs `apps` split:

```
Tier 1: Platform RGDs (lives in cluster, rarely changes)
├── ExternalSecretRGD   — wraps ExternalSecret (Bitwarden-backed)
├── HttprouteRGD        — wraps Gateway API HTTPRoute
├── VolsyncBackupRGD    — wraps Volsync ReplicationSource
└── KopiaMaintenanceRGD — wraps scheduled Kopia maintenance CronJob

Tier 2: Application RGDs (one per app, owns app-specific values)
├── MediaAppRGD         — sonarr, radarr, bazarr, prowlarr, etc.
├── SimpleAppRGD        — flaresolverr, recyclarr (no persistence)
├── StatefulAppRGD     — plex, jellyfin, paperless-ngx (custom charts + PG wiring)
└── SureAppRGD          — custom Sure Rails chart

Note: Deployment+Service are inlined in Tier-2 RGDs, not separate Tier-1 RGDs.
The bjw-s app-template chart is replaced entirely by raw Deployment+Service
templates in Kro, not chained from a separate RGD.
```

Each Tier-2 RGD:

- Inlines Deployment + Service directly (no chaining needed for these)
- Chains ExternalSecretRGD when secrets are needed
- Chains HttprouteRGD when route is enabled
- Chains VolsyncBackupRGD when persistence is configured

This avoids unnecessary indirection while keeping shared logic in platform RGDs.

### Naming convention

- RGD names: `externalsecret`, `httproute`, `volsyncbackup`, `mediaapp`, `simpleapp`, `statefulapp`, `sureapp`
- Resource IDs (within RGD): camelCase only, no hyphens (`mediaAppDeployment`, `mediaAppService`)
- Custom types: PascalCase (`ContainerResources`, `NfsMount`, `RouteSpec`)
- Instance kinds: PascalCase (`MediaApp`, `SimpleApp`, `StatefulApp`, `SureApp`)
- Group: `kro.run` (default)

### Schema design for MediaAppRGD

The `app.k` schema maps cleanly to Kro SimpleSchema:

```yaml
spec:
  name: string | required=true
  namespace: string | default="media"
  image:
    repository: string | required=true
    tag: string | required=true
    pullPolicy: string | default="IfNotPresent"
  port: integer | required=true
  controllerType: string | default="statefulset" | enum="deployment,statefulset"
  replicas: integer | default=1 | minimum=1
  env: "map[string]string"
  envFromSecret: "map[string]string"
  resources:
    requests: ContainerResources
    limits: ContainerResources
  probe: ProbeSpec
  securityContext: SecurityContextSpec | default={runAsUser: 1999, runAsGroup: 1999, fsGroup: 1999}
  persistence: PersistenceSpec
  nfs: NfsMount
  route: RouteSpec
  secretRef: "map[string]string"  # secret-name → key mappings
status:
  ready: ${mediaAppDeployment.status.readyReplicas == schema.spec.replicas}
  availableReplicas: ${mediaAppDeployment.status.availableReplicas}
additionalPrinterColumns:
  - jsonPath: .spec.replicas
    name: Replicas
    type: integer
  - jsonPath: .spec.image.tag
    name: Tag
    type: string
  - jsonPath: .status.availableReplicas
    name: Available
    type: integer
```

Where custom types are defined in the `types:` block:

```yaml
types:
  ContainerResources:
    cpu: string
    memory: string
  ProbeSpec:
    path: string | required=true
    port: integer | required=true
    initialDelaySeconds: int | default=0
    periodSeconds: int | default=10
    timeoutSeconds: int | default=1
    failureThreshold: int | default=3
  SecurityContextSpec:
    runAsUser: int | default=1999
    runAsGroup: int | default=1999
    fsGroup: int | default=1999
    fsGroupChangePolicy: string | default="OnRootMismatch"
  PersistenceSpec:
    name: string | default="config"
    size: string | required=true
    storageClass: string | default="ceph-block"
    accessMode: string | default="ReadWriteOnce"
    mountPath: string | default="/config"
  NfsMount:
    server: string | required=true
    path: string | required=true
    mountPath: string | default="/data"
  RouteSpec:
    enabled: boolean | default=false
    hostname: string | required=true
    parentName: string | default="private"
    parentNamespace: string | default="networking"
    parentSectionName: string | default="https"
```

### Handling what Kro can't natively do

Kro RGDs cannot use kustomize features. Instead:

| Old kustomize pattern                            | Kro equivalent                                                 |
| ------------------------------------------------ | -------------------------------------------------------------- |
| `patchesJson6902` for defaults                   | Defaults in schema fields (CEL fills them in)                  |
| `components/` for volsync                        | VolsyncBackupRGD chained resource when persistence configured  |
| `components/` for HPA                            | Defer — no native HPA in Kro yet                               |
| `postBuild.substitute` (APP, CLAIM, VOLSYNC\_\*) | Directly in instance spec as schema fields                     |
| `commonMetadata.labels`                          | Set in resource templates once                                 |
| `reloader` annotation                            | `reloader.stakater.com/auto: "true"` in Deployment annotations |
| SOPS decryption                                  | Flux Kustomization decrypts YAML before Kro sees it            |

### Resource templates (simplified for sonarr)

The Deployment/StatefulSet distinction uses two conditional resource blocks:

```yaml
resources:
  - id: mediaAppStatefulset
    includeWhen:
      - ${schema.spec.controllerType == "statefulset"}
    template:
      apiVersion: apps/v1
      kind: StatefulSet
      metadata:
        name: ${schema.spec.name}
        namespace: ${schema.spec.namespace}
        annotations:
          reloader.stakater.com/auto: "true"
        labels:
          app.kubernetes.io/name: ${schema.spec.name}
      spec:
        serviceName: ${schema.spec.name}
        replicas: ${schema.spec.replicas}
        selector:
          matchLabels:
            app: ${schema.spec.name}
        template:
          metadata:
            labels:
              app: ${schema.spec.name}
          spec:
            securityContext: ${schema.spec.securityContext}
            containers:
              - name: app
                image: "${schema.spec.image.repository}:${schema.spec.image.tag}"
                imagePullPolicy: ${schema.spec.image.pullPolicy}
                ports:
                  - containerPort: ${schema.spec.port}
                env: ${envVars}
                envFrom: ${envFromSecretRefs}
                readinessProbe:
                  httpGet:
                    path: ${schema.spec.probe.path}
                    port: ${schema.spec.port}
                  initialDelaySeconds: ${schema.spec.probe.initialDelaySeconds}
                  periodSeconds: ${schema.spec.probe.periodSeconds}
                resources: ${schema.spec.resources}
                securityContext:
                  allowPrivilegeEscalation: false
                  capabilities:
                    drop: ["ALL"]
            volumes: ${nfsVolumes}
        volumeClaimTemplates:
          - metadata:
              name: ${schema.spec.persistence.name}
            spec:
              accessModes: [${schema.spec.persistence.accessMode}]
              storageClassName: ${schema.spec.persistence.storageClass}
              resources:
                requests:
                  storage: ${schema.spec.persistence.size}
    readyWhen:
      - ${mediaAppStatefulset.status.readyReplicas > 0}

  - id: mediaAppDeployment
    includeWhen:
      - ${schema.spec.controllerType == "deployment"}
    template:
      apiVersion: apps/v1
      kind: Deployment
      metadata:
        name: ${schema.spec.name}
        namespace: ${schema.spec.namespace}
        annotations:
          reloader.stakater.com/auto: "true"
        labels:
          app.kubernetes.io/name: ${schema.spec.name}
      spec:
        replicas: ${schema.spec.replicas}
        selector:
          matchLabels:
            app: ${schema.spec.name}
        template:
          metadata:
            labels:
              app: ${schema.spec.name}
          spec:
            securityContext: ${schema.spec.securityContext}
            containers:
              - name: app
                image: "${schema.spec.image.repository}:${schema.spec.image.tag}"
                imagePullPolicy: ${schema.spec.image.pullPolicy}
                ports:
                  - containerPort: ${schema.spec.port}
                env: ${envVars}
                envFrom: ${envFromSecretRefs}
                readinessProbe:
                  httpGet:
                    path: ${schema.spec.probe.path}
                    port: ${schema.spec.port}
                  initialDelaySeconds: ${schema.spec.probe.initialDelaySeconds}
                  periodSeconds: ${schema.spec.probe.periodSeconds}
                resources: ${schema.spec.resources}
                securityContext:
                  allowPrivilegeEscalation: false
                  capabilities:
                    drop: ["ALL"]
            volumes: ${nfsVolumes}
    readyWhen:
      - ${mediaAppDeployment.status.availableReplicas > 0}

  - id: mediaAppService
    template:
      apiVersion: v1
      kind: Service
      metadata:
        name: ${schema.spec.name}
        namespace: ${schema.spec.namespace}
      spec:
        selector:
          app: ${schema.spec.name}
        ports:
          - protocol: TCP
            port: ${schema.spec.port}
            targetPort: ${schema.spec.port}

  - id: mediaAppExternalSecret
    includeWhen:
      - ${size(schema.spec.secretRef) > 0}
    externalRef:
      apiVersion: external-secrets.io/v1
      kind: ClusterSecretStore
      metadata:
        name: bitwarden-secrets-manager
    template:
      apiVersion: external-secrets.io/v1
      kind: ExternalSecret
      metadata:
        name: ${schema.spec.name}
        namespace: ${schema.spec.namespace}
      spec:
        refreshInterval: 3h
        secretStoreRef:
          name: bitwarden-secrets-manager
          kind: ClusterSecretStore
        target:
          name: ${schema.spec.name}
        dataFrom:
          - extract:
              key: infra-media-secrets

  - id: mediaAppHttproute
    includeWhen:
      - ${schema.spec.route.enabled}
    readyWhen:
      - ${mediaAppHttproute.status.conditions.exists(c, c.type == "Accepted" && c.status == "True")}
    template:
      apiVersion: gateway.networking.k8s.io/v1
      kind: HTTPRoute
      metadata:
        name: ${schema.spec.name}
        namespace: ${schema.spec.namespace}
      spec:
        parentRefs:
          - name: ${schema.spec.route.parentName}
            namespace: ${schema.spec.route.parentNamespace}
            sectionName: ${schema.spec.route.parentSectionName}
        hostnames: [${schema.spec.route.hostname}]
        rules:
          - backendRefs:
              - name: ${mediaAppService.metadata.name}
                port: ${schema.spec.port}
```

### NFS volume mounts

NFS is expressed as volume mounts directly in the container spec:

```yaml
volumes:
  - name: nfs-data
    nfs:
      server: ${schema.spec.nfs.server}
      path: ${schema.spec.nfs.path}
volumeMounts:
  - name: nfs-data
    mountPath: ${schema.spec.nfs.mountPath}
```

### What stays in Flux

Flux still owns:

- `flux-system/` namespace and Flux controller deployment
- `sources` (HelmRepository for bjw-s-labs, authentik; GitRepository for chkpwd-ops)
- `core/` Kustomization (kro, cert-manager, cilium, prometheus, volsync, external-secrets, etc.)
- RGD definitions themselves (applied via Flux core Kustomization)
- Top-level `apps/` Kustomization (references per-app Kro instance YAML)

What Flux NO LONGER owns:

- Per-app `helm-release.yml` files → replaced by Kro instance CRs
- Per-app `flux-kustomization.yml` files → replaced by Kro instance CRs
- Per-app `kustomization.yml` → replaced by top-level apps Kustomization referencing Kro instance YAML
- KCL code generation pipeline → removed entirely

### Access control (aggregation mode)

Create ClusterRole for each resource type Kro manages:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  labels:
    rbac.kro.run/aggregate-to-controller: "true"
  name: kro:controller:mediaapp
rules:
  - apiGroups: ["kro.run"]
    resources: ["mediaapps"]
    verbs: ["*"]
  - apiGroups: ["apps"]
    resources: ["deployments", "statefulsets"]
    verbs: ["*"]
  - apiGroups: [""]
    resources: ["services", "configmaps", "secrets"]
    verbs: ["*"]
  - apiGroups: ["gateway.networking.k8s.io"]
    resources: ["httproutes"]
    verbs: ["*"]
  - apiGroups: ["external-secrets.io"]
    resources: ["externalsecrets"]
    verbs: ["*"]
  - apiGroups: ["volsync.backube"]
    resources: ["replicationsources", "replicationdestinations"]
    verbs: ["*"]
```

Apply via Flux Kustomization in core.

## Migration Sequence

### Phase 0 — Bootstrap (do once)

1. Install kro: `helm install kro oci://registry.k8s.io/kro/charts/kro --namespace kro-system --create-namespace`
2. Install kro's aggregation ClusterRoles via Flux core Kustomization
3. Create `rgd/` directory structure in the repo

### Phase 1 — ExternalSecretRGD and HttprouteRGD (Tier 1)

4. Create `rgd/externalsecret-rgd.yaml` — wraps ExternalSecret with Bitwarden ClusterSecretStore
5. Create `rgd/httproute-rgd.yaml` — wraps HTTPRoute with configurable parentRefs
6. Apply to cluster, verify CRDs register, add to Flux core Kustomization
7. Create first Kro instance: migrate the sonarr ExternalSecret as a Kro instance

### Phase 2 — MediaAppRGD (Tier 2, first app)

8. Create `rgd/mediaapp-rgd.yaml` — Deployment + StatefulSet + Service + optional ExternalSecret + optional HTTPRoute
9. Migrate sonarr: write `apps/sonarr/kro-instance.yaml`
10. Remove `apps/sonarr/helm-release.yml`, `apps/sonarr/external-secret.yml`, `apps/sonarr/flux-kustomization.yml`, `apps/sonarr/kustomization.yml`
11. Add sonarr's kro-instance.yaml to top-level apps Kustomization
12. Verify: `kubectl get mediaapp sonarr`, child resources created correctly

### Phase 3 — Batch migrate remaining MediaApp apps (radarr, bazarr, prowlarr, sabnzbd, qbittorrent, etc.)

13. Write Kro instance YAML for each app using MediaAppRGD
14. Remove old per-app files for each migrated app
15. Add to apps Kustomization

### Phase 4 — Migrate SimpleAppRGD (flaresolverr, recyclarr, tautulli, etc.)

16. Create `rgd/simpleapp-rgd.yaml` — Deployment + Service + optional HTTPRoute (no persistence)

### Phase 5 — Migrate StatefulAppRGD (plex, jellyfin, paperless-ngx, authentik, etc.)

17. Create `rgd/statefulapp-rgd.yaml` — StatefulSet + Service + optional PG wiring + optional HTTPRoute
18. These apps use custom helm charts or CloudNativePG — handle via raw Deployment/StatefulSet templates

### Phase 6 — VolsyncBackupRGD (Tier 1)

19. Create `rgd/volsyncbackup-rgd.yaml` — wraps Volsync ReplicationSource with schedule, retention
20. Chain into MediaAppRGD for apps that need backup

### Phase 7 — SureAppRGD

21. Create `rgd/sureapp-rgd.yaml` — handles the custom Sure Helm chart's multi-component structure (web + sidekiq + optional CNPG + optional Redis)
22. Consider whether this stays as a HelmRelease with Kro wrapping the surrounding infrastructure instead of the chart itself

### Phase 8 — Cleanup

23. Delete all `flux-kustomization.yml` files under `apps/*/`
24. Delete all `kustomization.yml` files under `apps/*/`
25. Remove the `kcl/` directory entirely
26. Update `flux/cluster.yml` to point apps Kustomization at the flattened Kro instance YAML list

### File structure after migration

```
kubernetes/
├── flux/
│   ├── cluster.yml              # sources + core + apps (unchanged structure, changed contents)
│   └── sources/                # unchanged
├── core/                        # unchanged (cert-manager, cilium, etc.)
│   └── kro-clusterroles.yml     # NEW — aggregation ClusterRoles for Kro
├── rgd/                         # NEW — Kro ResourceGraphDefinitions
│   ├── externalsecret-rgd.yaml
│   ├── httproute-rgd.yaml
│   ├── volsyncbackup-rgd.yaml
│   ├── mediaapp-rgd.yaml
│   ├── simpleapp-rgd.yaml
│   └── statefulapp-rgd.yaml
└── apps/
    ├── sonarr/
    │   └── kro-instance.yaml   # Kro instance (1 file, replaces 4 files)
    ├── radarr/
    │   └── kro-instance.yaml
    └── ...
```

### RBAC (aggregation mode)

Will need ClusterRoles for these GVKs:

- `kro.run/v1alpha1` → `ResourceGraphDefinition` (always needed by kro itself)
- `kro.run/v1alpha1` → each generated kind (`mediaapp`, `simpleapp`, etc.)
- `apps/v1` → `Deployment`, `StatefulSet`
- `v1` → `Service`, `ConfigMap`, `Secret`, `PersistentVolumeClaim`
- `gateway.networking.k8s.io/v1` → `HTTPRoute`
- `external-secrets.io/v1` → `ExternalSecret`
- `volsync.backube/v1alpha1` → `ReplicationSource`, `ReplicationDestination`
- `rbac.authorization.k8s.io/v1` → `Role`, `RoleBinding` (if namespace-scoped)

## Limitations and Risks

### What is intentionally NOT migrated to Kro:

- Core infrastructure (cert-manager, cilium, prometheus, etc.) — stays as HelmReleases via Flux
- Rook Ceph, CloudNativePG operators and CRs — managed by their own controllers
- Flux itself

### What is deferred:

- `sure` custom Helm chart — complex subchart structure (CNPG, Redis); migrate after simpler apps are stable
- HPA — no native HPA resource in Kro yet; can add HorizontalPodAutoscaler as a resource in a future RGD update
- Grafana dashboard provisioning — handled separately by Grafana Operator

### Known Kro limitations (from docs):

- **No multi-version CRD support**: schema changes are breaking changes; no in-place version migration
- **No fine-grained resource lifecycle**: create/update/delete behavior per resource not yet configurable
- **No configurable deletion policy**: owner references are optional, deletion order handled by Kro ApplySet
- **Floating point comparison**: avoid comparing `float` types for equality in `readyWhen`/`includeWhen` — use integers
- **Empty collections are ready**: if `forEach` iterator is empty, zero resources created (not an error)
- **Collection size limit**: max 1000 items per collection (configurable), max 10 dimensions
- **ownerReferences risks**: cross-namespace and cluster-scoped resources fail; deletion order not guaranteed
- **GraphRevision failures block instances**: if latest revision fails compilation, instances stop progressing (no auto-rollback)

### Risks and mitigations:

| Risk                                               | Mitigation                                                                                                    |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| RGD schema change breaks existing instances        | Use additive changes only; test breaking-change annotation `kro.run/allow-breaking-changes: "true"` carefully |
| Kro controller goes down                           | Kro instances persist in etcd; controller restarts and reconciles                                             |
| External secrets not resolving                     | Kro waits for ExternalSecret with `readyWhen`; External Secrets Operator must be healthy                      |
| NFS server unreachable                             | Deployment will be `ImagePullBackOff` or `CrashLoopBackOff` — standard Kubernetes behavior                    |
| RGD validation fails on bad CEL expression         | Static analysis catches at RGD creation time; test RGD in dev cluster first                                   |
| ArgoCD tracking (if switching from Flux to ArgoCD) | Add owner references + tracking annotations per FAQ                                                           |
| Kopia maintenance CronJob                          | VolsyncBackupRGD handles ReplicationSource; separate RGD for maintenance schedule                             |

## Validation criteria

At the end of each phase:

- `kubectl get rgd` → all RGDs with `state: Active`
- `kubectl get mediaapp` → instance with `status.state: Active`
- `kubectl get deployment,svc,externalsecret,httproute -l app.kubernetes.io/managed-by=kro` → expected children
- Flux `flux get kustomizations` → all healthy with no sync errors
- No HelmRelease YAML files remain under `apps/*/`
- Deleting a Kro instance cascades-delete all child resources
- `kubectl describe rgd <name>` → no validation errors, `GraphRevisionsResolved: True`
- `kubectl get gr` → at least one revision with `READY=True`
- Printer columns work: `kubectl get mediaapp` shows name/replicas/tag/available columns
- `kubectl get mediaapp sonarr -o yaml` → status block shows `ready` and `availableReplicas`

## Key decisions to make before starting

1. **Custom API group**: use `kro.run` (default) or register `chkpwd.io`? Default is fine for now.
2. **Single RGD per app type** or **one RGD per app**? Plan uses one RGD per app type (MediaAppRGD, SimpleAppRGD, etc.) — users create instances. Alternatively, one RGD per app with app-specific defaults baked in.
3. **Deploy kro via Helm or raw manifests**? Helm is simpler (`helm install kro ...`).
4. **Keep Flux for driving instances** or **switch to `kubectl apply` directly**? Plan keeps Flux for consistency with existing workflow.
5. **ClusterRole strategy**: one aggregated ClusterRole per RGD family, or one per RGD?

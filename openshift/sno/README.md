# OpenShift SNO - Agent-based Installer

Single Node OpenShift at `sno.chkpwd.com` (`10.0.10.55`), installed via the agent-based CLI installer on a Proxmox VM.

## Prerequisites

- `openshift-install` CLI (OCP 4.20+)
- Pull secret from [Red Hat Console](https://console.redhat.com/openshift/install/pull-secret)
- SSH key at `~/.ssh/ocp_sno_ed25519`
- `nmstatectl` installed locally (validates NMState config during ISO generation)

## Setup

1. Add your pull secret to `install-config.yaml` — replace `REPLACE_WITH_PULL_SECRET` with the JSON string (single line, single-quoted).

2. Generate the agent ISO:

   ```bash
   # The installer consumes and deletes the configs, so work from a copy
   cp -r /Users/chkpwd/code/iac/openshift/sno /tmp/sno-install
   openshift-install agent create image --dir /tmp/sno-install
   ```

3. Upload the ISO to Proxmox and boot the VM from it.

   > Before the node reboots after writing to disk, change the VM boot order to disk-first
   > or remove the ISO. Otherwise it boots back into the installer.

4. Monitor the install:

   ```bash
   openshift-install agent wait-for install-complete --dir /tmp/sno-install
   ```

5. Access the cluster:

   ```bash
   export KUBECONFIG=/tmp/sno-install/auth/kubeconfig
   oc get nodes
   ```

## DNS Records (Terraform)

Defined in [`terraform/gravity/dns.tf`](../../terraform/gravity/dns.tf).

| Record                 | Type | Value      |
| ---------------------- | ---- | ---------- |
| api.sno.chkpwd.com     | A    | 10.0.10.55 |
| api-int.sno.chkpwd.com | A    | 10.0.10.55 |
| \*.apps.sno.chkpwd.com | A    | 10.0.10.55 |

---

## install-config.yaml Reference

[Full parameter reference](https://docs.openshift.com/container-platform/4.17/installing/installing_with_agent_based_installer/installation-config-parameters-agent.html)

| Field                                    | Value               | Description                                                                                                                                                                                                                                             |
| ---------------------------------------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `apiVersion`                             | `v1`                | Always `v1`.                                                                                                                                                                                                                                            |
| `baseDomain`                             | `chkpwd.com`        | Base DNS domain. Cluster accessible at `sno.chkpwd.com`. [Docs](https://docs.openshift.com/container-platform/4.17/installing/installing_bare_metal/installing-bare-metal.html#installation-dns-user-infra_installing-bare-metal)                       |
| `compute[].name`                         | `worker`            | Machine pool name. Must be `worker`.                                                                                                                                                                                                                    |
| `compute[].replicas`                     | `0`                 | `0` for SNO — the single node handles both control plane and workloads.                                                                                                                                                                                 |
| `compute[].architecture`                 | `amd64`             | CPU architecture.                                                                                                                                                                                                                                       |
| `controlPlane.name`                      | `master`            | Must be `master`.                                                                                                                                                                                                                                       |
| `controlPlane.replicas`                  | `1`                 | `1` for SNO, `3` for HA.                                                                                                                                                                                                                                |
| `controlPlane.architecture`              | `amd64`             | CPU architecture.                                                                                                                                                                                                                                       |
| `metadata.name`                          | `sno`               | Cluster name. Forms `sno.chkpwd.com` with `baseDomain`.                                                                                                                                                                                                 |
| `networking.clusterNetwork[].cidr`       | `10.128.0.0/14`     | Pod IP range. Must not overlap with host or service networks. [Docs](https://docs.openshift.com/container-platform/4.17/installing/installing_bare_metal/installing-bare-metal.html#installation-configuration-parameters_installing-bare-metal)        |
| `networking.clusterNetwork[].hostPrefix` | `23`                | Per-node subnet prefix. `/23` = 510 pod IPs per node.                                                                                                                                                                                                   |
| `networking.networkType`                 | `OVNKubernetes`     | Required for `platform: none`, default since OCP 4.12. [Docs](https://docs.openshift.com/container-platform/4.17/networking/ovn_kubernetes_network_provider/about-ovn-kubernetes.html)                                                                  |
| `networking.serviceNetwork[]`            | `172.30.0.0/16`     | ClusterIP service range. Must not overlap with cluster or host networks.                                                                                                                                                                                |
| `platform.none`                          | `{}`                | No infrastructure provider. Required for SNO / bare metal without IPI. [Docs](https://docs.openshift.com/container-platform/4.17/installing/installing_bare_metal/installing-bare-metal.html#installation-bare-metal-config-yaml_installing-bare-metal) |
| `fips`                                   | `false`             | FIPS 140-2 mode. [Docs](https://docs.openshift.com/container-platform/4.17/installing/installing-fips.html)                                                                                                                                             |
| `pullSecret`                             | `'{"auths":...}'`   | Pull secret JSON from Red Hat (single-quoted). Required for `quay.io` and `registry.redhat.io`. Get it from [console.redhat.com](https://console.redhat.com/openshift/install/pull-secret).                                                             |
| `sshKey`                                 | `'ssh-ed25519 ...'` | Public key injected into `core` user's `authorized_keys`. For emergency node access.                                                                                                                                                                    |

---

## agent-config.yaml Reference

[Full parameter reference](https://docs.openshift.com/container-platform/4.17/installing/installing_with_agent_based_installer/preparing-to-install-with-agent-based-installer.html)

### Top-level fields

| Field                    | Value         | Description                                                                                                                                                                                                                                                                                                    |
| ------------------------ | ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `apiVersion`             | `v1alpha1`    | Agent config API version.                                                                                                                                                                                                                                                                                      |
| `kind`                   | `AgentConfig` | Always `AgentConfig`.                                                                                                                                                                                                                                                                                          |
| `metadata.name`          | `sno`         | Must match `metadata.name` in `install-config.yaml`.                                                                                                                                                                                                                                                           |
| `rendezvousIP`           | `10.0.10.55`  | Node running bootstrap services (assisted-service). For SNO, the only node. [Docs](https://docs.openshift.com/container-platform/4.17/installing/installing_with_agent_based_installer/preparing-to-install-with-agent-based-installer.html#agent-host-config_preparing-to-install-with-agent-based-installer) |
| `additionalNTPSources[]` | `10.0.10.1`   | NTP server — MikroTik router. The assisted installer validates NTP sync before proceeding.                                                                                                                                                                                                                     |

### hosts[] fields

| Field                     | Value               | Description                                                          |
| ------------------------- | ------------------- | -------------------------------------------------------------------- |
| `hostname`                | `sno`               | Hostname for this node.                                              |
| `role`                    | `master`            | Must be `master` for SNO.                                            |
| `interfaces[].name`       | `ens18`             | Interface name as seen by the OS.                                    |
| `interfaces[].macAddress` | `bc:24:11:df:af:4d` | MAC address. Used to match the host to this config during discovery. |

### hosts[].networkConfig (NMState)

Uses [NMState](https://nmstate.io/) declarative format. [OpenShift NMState docs](https://docs.openshift.com/container-platform/4.17/networking/k8s_nmstate/k8s-nmstate-about-the-k8s-nmstate-operator.html)

#### interfaces[]

| Field           | Value               | Description                                                                                                                                                                                                                     |
| --------------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `name`          | `ens18`             | Must match `hosts[].interfaces[].name`.                                                                                                                                                                                         |
| `type`          | `ethernet`          | Options: `ethernet`, `bond`, `vlan`, `bridge`, etc.                                                                                                                                                                             |
| `state`         | `up`                | Options: `up`, `down`, `absent`.                                                                                                                                                                                                |
| `mac-address`   | `bc:24:11:df:af:4d` | Interface MAC.                                                                                                                                                                                                                  |
| `ipv4.enabled`  | `true`              | Enable IPv4.                                                                                                                                                                                                                    |
| `ipv4.dhcp`     | `true`              | Use DHCP. Set `false` for static IP.                                                                                                                                                                                            |
| `ipv4.auto-dns` | `false`             | Must be `false`. When `true`, DHCP pushes `chkpwd.com` as a search domain, which causes `*.sno.chkpwd.com` queries to also try `*.sno.chkpwd.com.chkpwd.com` — that resolves via Cloudflare and breaks wildcard DNS validation. |
| `ipv6.enabled`  | `false`             | IPv6 disabled.                                                                                                                                                                                                                  |

#### dns-resolver.config

| Field      | Value       | Description                                                                                                                                   |
| ---------- | ----------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `server[]` | `10.0.10.4` | Internal Gravity DNS server with the authoritative `sno.chkpwd.com` zone. Must not use public DNS — Cloudflare proxy records would interfere. |
| `search[]` | `[]`        | Empty. Any search domain would cause double-suffix DNS lookups that break validation.                                                         |

---

## LVM Storage

Dynamic PV provisioning via LVM thin pools on local disk. The secondary 128GB disk (`/dev/sdb`) is managed by the LVM Storage Operator through the TopoLVM CSI driver.

Manifests: [`manifests/lvm-storage/`](manifests/lvm-storage/)

### Setup

Apply in order — the operator must be running before creating the LVMCluster CR:

```bash
export KUBECONFIG=/tmp/sno-install/auth/kubeconfig

# 1. Create the namespace
oc apply -f manifests/lvm-storage/namespace.yaml

# 2. Create the OperatorGroup and Subscription
oc apply -f manifests/lvm-storage/operatorgroup.yaml
oc apply -f manifests/lvm-storage/subscription.yaml

# 3. Wait for the operator to install
oc wait csv -n openshift-storage -l operators.coreos.com/lvms-operator.openshift-storage --for=jsonpath='{.status.phase}'=Succeeded --timeout=180s

# 4. Create the LVMCluster
oc apply -f manifests/lvm-storage/lvmcluster.yaml

# 5. Verify
oc get lvmcluster -n openshift-storage
oc get sc
oc get volumesnapshotclass
```

### Created Resources

The operator creates these after reconciling the LVMCluster CR:

| Resource            | Name                 | Details                                                              |
| ------------------- | -------------------- | -------------------------------------------------------------------- |
| StorageClass        | `lvms-vg1` (default) | Provisioner: `topolvm.io`, `WaitForFirstConsumer`, expansion enabled |
| VolumeSnapshotClass | `lvms-vg1`           | Driver: `topolvm.io`, deletion policy: Delete                        |

### Manifest Reference

#### Namespace (`namespace.yaml`)

Creates `openshift-storage`.

#### OperatorGroup (`operatorgroup.yaml`)

| Field                     | Value               | Description                                                               |
| ------------------------- | ------------------- | ------------------------------------------------------------------------- |
| `spec.targetNamespaces[]` | `openshift-storage` | Scopes the operator to this namespace. Required by OLM before installing. |

#### Subscription (`subscription.yaml`)

[OLM Subscription docs](https://olm.operatorframework.io/docs/concepts/crds/subscription/)

| Field                      | Value                   | Description                                                                                                                                                             |
| -------------------------- | ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `spec.channel`             | `stable-4.21`           | Operator channel. Match to OCP minor version. List available: `oc get packagemanifest lvms-operator -n openshift-marketplace -o jsonpath='{.status.channels[*].name}'`. |
| `spec.installPlanApproval` | `Automatic`             | Auto-upgrade when new versions appear.                                                                                                                                  |
| `spec.name`                | `lvms-operator`         | Package name in the catalog.                                                                                                                                            |
| `spec.source`              | `redhat-operators`      | Default Red Hat catalog.                                                                                                                                                |
| `spec.sourceNamespace`     | `openshift-marketplace` | CatalogSource namespace.                                                                                                                                                |

#### LVMCluster (`lvmcluster.yaml`)

[LVM Storage docs](https://docs.openshift.com/container-platform/4.17/storage/persistent_storage/persistent_storage_using_lvms/logical-volume-manager-storage-using-rhol.html)

| Field                                                            | Value                                    | Description                                                                                |
| ---------------------------------------------------------------- | ---------------------------------------- | ------------------------------------------------------------------------------------------ |
| `spec.storage.deviceClasses[].name`                              | `vg1`                                    | VG name. StorageClass will be `lvms-vg1`.                                                  |
| `spec.storage.deviceClasses[].default`                           | `true`                                   | Makes `lvms-vg1` the cluster default StorageClass.                                         |
| `spec.storage.deviceClasses[].deviceSelector.paths[]`            | `/dev/sdb`                               | Secondary 128GB disk. Do not include `/dev/sda` (OS disk).                                 |
| `spec.storage.deviceClasses[].thinPoolConfig.name`               | `thin-pool-1`                            | LVM thin pool name.                                                                        |
| `spec.storage.deviceClasses[].thinPoolConfig.sizePercent`        | `90`                                     | Thin pool gets 90% of VG. Remaining 10% reserved for LVM metadata.                         |
| `spec.storage.deviceClasses[].thinPoolConfig.overprovisionRatio` | `10`                                     | Max ratio of provisioned to actual capacity. `10` on ~115GB = up to ~1.15TB of PVC claims. |
| `spec.storage.deviceClasses[].nodeSelector`                      | `node-role.kubernetes.io/worker: Exists` | SNO has both `master` and `worker` roles, so `worker` matches.                             |

---

## Kasten Monitoring (User Workload Monitoring)

Feeds Kasten K10 catalog metrics into OpenShift's built-in Prometheus + Alertmanager stack for backup status visibility and alerting.

Based on the [Veeam Kasten OpenShift Monitoring guide](https://veeamkasten.dev/kasten-openshift-monitoring).

Manifests: [`manifests/kasten-monitoring/`](manifests/kasten-monitoring/)

### How It Works

1. `cluster-monitoring-config` ConfigMap enables user workload monitoring — deploys a Prometheus instance in `openshift-user-workload-monitoring` that scrapes user-defined ServiceMonitors.
2. A NetworkPolicy allows ingress from `openshift-user-workload-monitoring` into `kasten-io` (Kasten has a `default-deny` policy).
3. A ServiceMonitor scrapes `catalog-svc` on port 8000 every 30s. The catalog exposes action counts, statuses, and PVC usage metrics.

### Setup

```bash
export KUBECONFIG=/tmp/sno-install/auth/kubeconfig

# 1. Enable user workload monitoring
oc apply -f manifests/kasten-monitoring/cluster-monitoring-config.yaml

# 2. Wait for user workload monitoring pods
oc get pods -n openshift-user-workload-monitoring -w

# 3. Allow monitoring namespace to scrape kasten-io
oc apply -f manifests/kasten-monitoring/networkpolicy.yaml

# 4. Create the ServiceMonitor
oc apply -f manifests/kasten-monitoring/servicemonitor.yaml

# 5. Create alert rules
oc apply -f manifests/kasten-monitoring/prometheusrule.yaml

# 6. Verify: Observe > Targets in the console, search for kasten-io
#    Alert rules: Observe > Alerting
```

### PromQL Queries

| Query                                                       | Description                                 |
| ----------------------------------------------------------- | ------------------------------------------- |
| `up{namespace="kasten-io"}`                                 | Scrape target health                        |
| `catalog_actions_count`                                     | All actions by status/type/policy/namespace |
| `catalog_actions_count{status="failed"}`                    | Failed actions                              |
| `increase(catalog_actions_count{status="failed"}[10m]) > 0` | Recent failures (last 10m)                  |
| `100 - catalog_persistent_volume_free_space_percent > 50`   | Catalog PVC usage > 50%                     |

### Manifest Reference

#### cluster-monitoring-config (`cluster-monitoring-config.yaml`)

| Field                                 | Value  | Description                                                                                                                                                                                                                                                   |
| ------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `data.config.yaml.enableUserWorkload` | `true` | Deploys `prometheus-operator`, `prometheus-user-workload`, and `thanos-ruler-user-workload` in `openshift-user-workload-monitoring`. [Docs](https://docs.openshift.com/container-platform/4.17/monitoring/enabling-monitoring-for-user-defined-projects.html) |

#### NetworkPolicy (`networkpolicy.yaml`)

| Field                                      | Value                                      | Description                                                                                       |
| ------------------------------------------ | ------------------------------------------ | ------------------------------------------------------------------------------------------------- |
| `spec.ingress[0].from[].namespaceSelector` | `name: openshift-user-workload-monitoring` | Allows scraping from monitoring namespace. Required due to Kasten's `default-deny` NetworkPolicy. |
| `spec.ingress[1].ports[].port`             | `http`                                     | Port 8000 — catalog metrics endpoint.                                                             |
| `spec.podSelector.matchLabels`             | `release: k10`                             | Targets all Kasten pods.                                                                          |

#### ServiceMonitor (`servicemonitor.yaml`)

[Prometheus ServiceMonitor docs](https://prometheus-operator.dev/docs/api-reference/api/#monitoring.coreos.com/v1.ServiceMonitor)

| Field                       | Value                | Description                         |
| --------------------------- | -------------------- | ----------------------------------- |
| `spec.endpoints[].interval` | `30s`                | Scrape interval.                    |
| `spec.endpoints[].port`     | `http`               | Named port on `catalog-svc` (8000). |
| `spec.endpoints[].scheme`   | `http`               | No TLS internally.                  |
| `spec.selector.matchLabels` | `component: catalog` | Selects `catalog-svc`.              |

#### PrometheusRule (`prometheusrule.yaml`)

Alert rules for the user workload Prometheus.

> Requires the label `openshift.io/prometheus-rule-evaluation-scope: leaf-prometheus` — without it, user workload Prometheus silently ignores the rule. This is OpenShift-specific; upstream Prometheus Operator does not require it.

| Alert                       | Severity | Expression                                                                 | Description                                                     |
| --------------------------- | -------- | -------------------------------------------------------------------------- | --------------------------------------------------------------- |
| `KastenBackupFailed`        | critical | `increase(catalog_actions_count{status="failed", type="backup"}[10m]) > 0` | Fires when a backup fails.                                      |
| `KastenExportFailed`        | critical | `increase(catalog_actions_count{status="failed", type="export"}[10m]) > 0` | Fires when an export fails (data not sent to location profile). |
| `KastenCatalogDiskHigh`     | warning  | `100 - catalog_persistent_volume_free_space_percent > 80`                  | Catalog PVC > 80% full (5m).                                    |
| `KastenCatalogDiskCritical` | critical | `100 - catalog_persistent_volume_free_space_percent > 95`                  | Catalog PVC > 95% full (5m).                                    |

---

## Garage (S3-compatible Object Store)

[Garage](https://garagehq.deuxfleurs.fr/) — S3-compatible object storage. Single-node instance used as a Kasten backup export target.

Manifests: [`manifests/garage/`](manifests/garage/)

### Prerequisites

- Helm repo: `helm repo add charts-derwitt-dev https://charts.derwitt.dev`
- Chart: `charts-derwitt-dev/garage` (v2.3.1, appVersion v2.2.0)

### Setup

```bash
export KUBECONFIG=/tmp/sno-install/auth/kubeconfig

# 1. Grant SCC (must be done before helm install)
oc adm policy add-scc-to-user nonroot-v2 -z garage -n garage
# Or apply the manifest:
# oc apply -f manifests/garage/scc-rolebinding.yaml

# 2. Deploy via Helm
helm install --create-namespace --namespace garage garage \
  charts-derwitt-dev/garage \
  -f manifests/garage/values.yaml

# 3. Wait for pod to be ready
oc wait pod/garage-0 -n garage --for=condition=Ready --timeout=120s

# 4. Configure cluster layout
NODE_ID=$(oc exec -n garage garage-0 -- ./garage status 2>&1 | grep garage-0 | awk '{print $1}')
oc exec -n garage garage-0 -- ./garage layout assign -z dc1 -c 1G $NODE_ID
oc exec -n garage garage-0 -- ./garage layout apply --version 1

# 5. Create a bucket and key
oc exec -n garage garage-0 -- ./garage bucket create bucket1
oc exec -n garage garage-0 -- ./garage key create bucket1-key
oc exec -n garage garage-0 -- ./garage bucket allow --read --write --owner bucket1 --key bucket1-key
```

### Changes from Upstream Values

The upstream values targeted minikube on arm64. Changes for SNO:

| Field                         | Original                    | SNO Override                     | Reason                                                      |
| ----------------------------- | --------------------------- | -------------------------------- | ----------------------------------------------------------- |
| `image.repository`            | `dxflrs/arm64_garage`       | Removed (defaults to amd64)      | amd64 host                                                  |
| `persistence.*.storageClass`  | `csi-hostpath-sc`           | `lvms-vg1`                       | LVM Storage on `/dev/sdb`                                   |
| `ingress.s3.api.className`    | `nginx`                     | `openshift-default`              | OpenShift router                                            |
| `ingress.s3.api.hosts[].host` | `s3-api.k8s.minikube.local` | `s3-api.apps.sno.chkpwd.com`     | Wildcard DNS                                                |
| `ingress.s3.api.annotations`  | `proxy-body-size: "0"`      | Removed                          | Not needed                                                  |
| `monitoring.metrics`          | Not set                     | `enabled: true` + ServiceMonitor | User workload monitoring                                    |
| SCC                           | N/A                         | `nonroot-v2` for `garage` SA     | Chart sets `runAsUser: 1000`, outside OpenShift's UID range |

### Values Reference (`values.yaml`)

| Field                                       | Value                        | Description                                |
| ------------------------------------------- | ---------------------------- | ------------------------------------------ |
| `garage.replicationFactor`                  | `1`                          | Single copy. No redundancy on single-node. |
| `garage.admin.token.create`                 | `true`                       | Auto-generate admin API token.             |
| `garage.admin.token.secret.create`          | `true`                       | Store admin token in a Secret.             |
| `garage.s3.api.region`                      | `garage`                     | S3 region for SDK config.                  |
| `garage.s3.api.rootDomain`                  | `.s3.garage.sno.chkpwd.com`  | DNS-style bucket access root.              |
| `garage.s3.web.rootDomain`                  | `.web.garage.sno.chkpwd.com` | Static website hosting root.               |
| `deployment.replicaCount`                   | `1`                          | Single replica.                            |
| `persistence.meta.storageClass`             | `lvms-vg1`                   | Metadata PVC (LMDB).                       |
| `persistence.meta.size`                     | `100Mi`                      | Metadata volume size.                      |
| `persistence.data.storageClass`             | `lvms-vg1`                   | Data PVC (object blocks).                  |
| `persistence.data.size`                     | `1Gi`                        | Data volume size.                          |
| `ingress.s3.api.enabled`                    | `true`                       | Expose S3 API via Ingress.                 |
| `ingress.s3.api.className`                  | `openshift-default`          | OpenShift router.                          |
| `ingress.s3.api.hosts[].host`               | `s3-api.apps.sno.chkpwd.com` | S3 API hostname.                           |
| `monitoring.metrics.enabled`                | `true`                       | Metrics on port 3903.                      |
| `monitoring.metrics.serviceMonitor.enabled` | `true`                       | ServiceMonitor for Prometheus scraping.    |

### Removing

```bash
helm delete --namespace garage garage
oc delete namespace garage
```

---

## Cassandra (Test Workload)

Single-node [Cassandra](https://cassandra.apache.org/) 4.1 StatefulSet used to test Kasten K10 backup and restore with a real stateful workload.

Manifests: [`manifests/cassandra/`](manifests/cassandra/)

### Setup

```bash
export KUBECONFIG=/tmp/sno-install/auth/kubeconfig

# 1. Create namespace and grant SCC
oc apply -f manifests/cassandra/namespace.yaml
oc apply -f manifests/cassandra/scc-rolebinding.yaml

# 2. Create the headless service and StatefulSet
oc apply -f manifests/cassandra/service.yaml
oc apply -f manifests/cassandra/statefulset.yaml

# 3. Wait for pod to be ready (~60-90s for Cassandra startup)
oc wait pod/cassandra-0 -n cassandra --for=condition=Ready --timeout=180s

# 4. Insert test data
oc exec -n cassandra cassandra-0 -- cqlsh -e "
CREATE KEYSPACE IF NOT EXISTS test_ks WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1};
CREATE TABLE IF NOT EXISTS test_ks.messages (id UUID PRIMARY KEY, body text);
INSERT INTO test_ks.messages (id, body) VALUES (uuid(), 'hello from cassandra');
INSERT INTO test_ks.messages (id, body) VALUES (uuid(), 'backup me');
INSERT INTO test_ks.messages (id, body) VALUES (uuid(), 'third row');
SELECT * FROM test_ks.messages;
"
```

### OpenShift SCC Notes

`cassandra:4.1` runs as UID/GID 999 and refuses to start as root. OpenShift assigns random UIDs from the namespace range by default, which doesn't include 999. The `nonroot-v2` SCC lets it run as 999 without `anyuid` or `privileged`.

### Manifest Reference

#### Namespace (`namespace.yaml`)

Creates `cassandra`.

#### SCC RoleBinding (`scc-rolebinding.yaml`)

| Field             | Value                             | Description                              |
| ----------------- | --------------------------------- | ---------------------------------------- |
| `roleRef.name`    | `system:openshift:scc:nonroot-v2` | Allows any non-root UID (including 999). |
| `subjects[].name` | `default`                         | Default SA in `cassandra` namespace.     |

#### Service (`service.yaml`)

| Field               | Value  | Description                                                                          |
| ------------------- | ------ | ------------------------------------------------------------------------------------ |
| `spec.clusterIP`    | `None` | Headless. Pods get stable DNS (`cassandra-0.cassandra.cassandra.svc.cluster.local`). |
| `spec.ports[].port` | `9042` | CQL native transport.                                                                |

#### StatefulSet (`statefulset.yaml`)

| Field                                               | Value                                               | Description                                                                                            |
| --------------------------------------------------- | --------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `spec.replicas`                                     | `1`                                                 | Single replica.                                                                                        |
| `spec.serviceName`                                  | `cassandra`                                         | Must match headless Service name.                                                                      |
| `spec.template.spec.securityContext.runAsUser`      | `999`                                               | Cassandra UID.                                                                                         |
| `spec.template.spec.securityContext.runAsGroup`     | `999`                                               | Cassandra GID.                                                                                         |
| `spec.template.spec.securityContext.fsGroup`        | `999`                                               | Volume ownership for `/var/lib/cassandra`.                                                             |
| `spec.template.spec.terminationGracePeriodSeconds`  | `120`                                               | Time for `nodetool drain` to flush memtables.                                                          |
| `containers[].image`                                | `docker.io/cassandra:4.1`                           | Do not use `gcr.io/google-samples/cassandra:v13` — it calls `su` internally, which fails on OpenShift. |
| `containers[].resources`                            | `500m CPU, 1Gi memory`                              | Cassandra needs ~512MB heap minimum.                                                                   |
| `env.MAX_HEAP_SIZE`                                 | `512M`                                              | JVM max heap. Must fit in the memory limit.                                                            |
| `env.HEAP_NEWSIZE`                                  | `100M`                                              | JVM young generation.                                                                                  |
| `env.CASSANDRA_SEEDS`                               | `cassandra-0.cassandra.cassandra.svc.cluster.local` | Points to itself for single-node.                                                                      |
| `env.CASSANDRA_CLUSTER_NAME`                        | `K8Demo`                                            | Must match across nodes in multi-node setups.                                                          |
| `lifecycle.preStop`                                 | `nodetool drain`                                    | Flush memtables and stop connections before shutdown.                                                  |
| `readinessProbe`                                    | `cqlsh -e 'SELECT now() FROM system.local'`         | Ready when CQL responds. 60s initial delay for startup.                                                |
| `volumeClaimTemplates[].storageClassName`           | `lvms-vg1`                                          | PVC stays `Pending` until pod is scheduled (`WaitForFirstConsumer`) — expected.                        |
| `volumeClaimTemplates[].resources.requests.storage` | `1Gi`                                               | Data volume.                                                                                           |

---

## Kasten K10 Backup (Location Profile & Policy)

Backs up the Cassandra namespace via volume snapshots and exports to Garage S3.

Manifests: [`manifests/kasten-backup/`](manifests/kasten-backup/)

### Prerequisites

- Kasten K10 in `kasten-io` namespace
- Garage S3 with bucket `bucket1` and key `bucket1-key` (see [Garage](#garage-s3-compatible-object-store))
- VolumeSnapshotClass `lvms-vg1` (see [LVM Storage](#lvm-storage))

### Architecture

```
cassandra namespace                kasten-io namespace              garage namespace
┌──────────────┐                  ┌──────────────────┐             ┌──────────────┐
│ cassandra-0  │  ← snapshot ←    │  K10 executor    │  → export → │  garage-0    │
│  PVC: 1Gi    │                  │  (data-mover)    │    (S3)     │  bucket1     │
│  lvms-vg1    │                  │                  │             │  :3900       │
└──────────────┘                  └──────────────────┘             └──────────────┘
                                         │
                                  VolumeSnapshotClass
                                     lvms-vg1
                                  (annotated with
                                   k10.kasten.io/
                                   is-snapshot-class)
```

1. K10 snapshots PVCs in `cassandra` using the annotated VolumeSnapshotClass (`lvms-vg1`).
2. A `data-mover` pod mounts the snapshot and streams data to Garage via `http://garage.garage.svc.cluster.local:3900`.

### Setup

```bash
export KUBECONFIG=/tmp/sno-install/auth/kubeconfig

# 1. Annotate the VolumeSnapshotClass for Kasten
#    (Use oc annotate — the LVM Storage Operator owns this resource)
oc annotate volumesnapshotclass lvms-vg1 k10.kasten.io/is-snapshot-class=true

# 2. Create the S3 credentials secret
oc apply -f manifests/kasten-backup/s3-credentials-secret.yaml

# 3. Create the location profile
oc apply -f manifests/kasten-backup/location-profile.yaml

# 4. Validate the profile from the K10 dashboard
#    Settings > Location Profiles > s3-bucket1 > Validate
#    Direct oc apply does NOT trigger validation — status stays empty {}.

# 5. Create the backup policy
oc apply -f manifests/kasten-backup/backup-policy.yaml

# 6. Run on-demand: Policies > cassandra-backup > Run Once
```

### Troubleshooting

#### "Failed to find VolumeSnapshotClass with annotation k10.kasten.io/is-snapshot-class=true"

The LVM Storage Operator creates `lvms-vg1` without this annotation. Add it:

```bash
oc annotate volumesnapshotclass lvms-vg1 k10.kasten.io/is-snapshot-class=true
```

This must be an annotation, not a label. Kasten only checks annotations.

#### Profile validation status stays `{}`

`oc apply` on a Profile CR does not trigger validation. Use the K10 dashboard (Settings > Location Profiles > Validate) or the BFF API (`/validateProfile/`).

#### PVC stays Pending

`lvms-vg1` uses `WaitForFirstConsumer`. PVCs stay `Pending` until a pod referencing them is scheduled. Not an error.

### Manifest Reference

#### S3 Credentials Secret (`s3-credentials-secret.yaml`)

| Field                              | Value                  | Description                                                                          |
| ---------------------------------- | ---------------------- | ------------------------------------------------------------------------------------ |
| `metadata.name`                    | `k10-s3-bucket1-creds` | Referenced by Profile CR `credential.secret.name`.                                   |
| `metadata.namespace`               | `kasten-io`            | Must be in the same namespace as the Profile.                                        |
| `stringData.aws_access_key_id`     | _(redacted)_           | Garage access key ID for `bucket1-key`. Created via `garage key create bucket1-key`. |
| `stringData.aws_secret_access_key` | _(redacted)_           | Garage secret key for `bucket1-key`.                                                 |

#### Location Profile (`location-profile.yaml`)

[Kasten Profile docs](https://docs.kasten.io/latest/api/profiles.html)

| Field                                           | Value                                         | Description                                                                    |
| ----------------------------------------------- | --------------------------------------------- | ------------------------------------------------------------------------------ |
| `spec.type`                                     | `Location`                                    | Backup export target.                                                          |
| `spec.locationSpec.type`                        | `ObjectStore`                                 | Options: `ObjectStore`, `FileStore`.                                           |
| `spec.locationSpec.credential.secretType`       | `AwsAccessKey`                                | S3-compatible stores use this type.                                            |
| `spec.locationSpec.credential.secret.name`      | `k10-s3-bucket1-creds`                        | Secret with access key and secret key.                                         |
| `spec.locationSpec.objectStore.objectStoreType` | `S3`                                          | Garage is S3-compatible.                                                       |
| `spec.locationSpec.objectStore.endpoint`        | `http://garage.garage.svc.cluster.local:3900` | Internal service endpoint. Port 3900, not 80/443. Avoids ingress/TLS overhead. |
| `spec.locationSpec.objectStore.name`            | `bucket1`                                     | Must already exist in Garage.                                                  |
| `spec.locationSpec.objectStore.region`          | `garage`                                      | Must match `garage.s3.api.region` in Garage config.                            |
| `spec.locationSpec.objectStore.skipSSLVerify`   | `true`                                        | Internal endpoint uses plain HTTP.                                             |

#### VolumeSnapshotClass Annotation (`volumesnapshotclass-annotation.yaml`)

Reference only — the VolumeSnapshotClass is owned by the LVM Storage Operator. Use `oc annotate` to avoid conflicts:

| Field                                                  | Value    | Description                                                                                                   |
| ------------------------------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------- |
| `metadata.annotations.k10.kasten.io/is-snapshot-class` | `"true"` | Tells K10 to use this class for snapshots. Without it, backups fail at "Snapshotting Application Components". |

#### Backup Policy (`backup-policy.yaml`)

[Kasten Policy docs](https://docs.kasten.io/latest/api/policies.html)

| Field                                                 | Value                                       | Description                                                                           |
| ----------------------------------------------------- | ------------------------------------------- | ------------------------------------------------------------------------------------- |
| `spec.frequency`                                      | `@onDemand`                                 | Manual trigger only. Other options: `@hourly`, `@daily`, `@weekly`, `@monthly`, cron. |
| `spec.selector.matchExpressions`                      | `k10.kasten.io/appNamespace In [cassandra]` | Targets `cassandra` namespace.                                                        |
| `spec.actions[0].action`                              | `backup`                                    | Volume snapshot of all PVCs + K8s manifest capture.                                   |
| `spec.actions[1].action`                              | `export`                                    | Export to off-cluster location profile.                                               |
| `spec.actions[1].exportParameters.profile.name`       | `s3-bucket1`                                | Must reference a validated Profile.                                                   |
| `spec.actions[1].exportParameters.exportData.enabled` | `true`                                      | Export actual PVC data. When `false`, only manifests are exported.                    |

### K10 Pod Roles During Backup

| Pod                     | Role                                                                                                                                                                                                            |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `dashboardbff-svc`      | UI orchestrator. Profile/policy CRUD, triggers runs, S3 validation (HeadBucket).                                                                                                                                |
| `controllermanager-svc` | Policy CR validation (`status.validation`, `status.hash`). Silent during execution.                                                                                                                             |
| `jobs-svc`              | Job queue management.                                                                                                                                                                                           |
| `executor-svc`          | Executes jobs: `fanout` → `queuingAndWaitingOnChildren` → `lockKubernetesNamespace` → `backupPreHook` → `Discover Kubernetes Objects` → `waitingOnKubernetesObjectSnapshots` → `monitoringAndLaunchingExports`. |
| `catalog-svc`           | Tracks artifacts/manifests. Metrics on port 8000.                                                                                                                                                               |
| `data-mover-svc`        | Ephemeral per-run. Mounts snapshot, exports PVC data to S3.                                                                                                                                                     |

### Inspecting the Kopia Repository

K10 uses [Kopia](https://kopia.io/) as its data mover. Exported data lives in a Kopia repo inside the S3 bucket. The `k10_repo_checker.sh` script (from Kasten) launches a temporary pod with Kopia CLI connected to the repo in read-only mode.

[Kasten k10tools documentation](https://docs.kasten.io/latest/operating/k10tools/)

#### Connecting

```bash
curl -s https://docs.kasten.io/downloads/8.0.12/tools/k10_repo_checker.sh | bash /dev/stdin \
  -r application \
  -o connect \
  -a cassandra \
  -p s3-bucket1 \
  -n kasten-io
```

This launches a `k10tools` pod to resolve credentials, creates a `debug-kopia-*` pod with Kopia configured, then deletes the `k10tools` pod.

#### Inspecting Snapshots

```bash
KOPIA_POD=debug-kopia-<suffix>

# List all snapshots
oc exec -n kasten-io $KOPIA_POD -- \
  env KOPIA_CONFIG_PATH=/tmp/kopia-repository.config \
  kopia snapshot list --all

# JSON details
oc exec -n kasten-io $KOPIA_POD -- \
  env KOPIA_CONFIG_PATH=/tmp/kopia-repository.config \
  kopia snapshot list --all --json

# Content statistics
oc exec -n kasten-io $KOPIA_POD -- \
  env KOPIA_CONFIG_PATH=/tmp/kopia-repository.config \
  kopia content stats
```

#### Example Output

Snapshot list:

```
k10-admin@<cluster-id>.cassandra.cassandra-data-cassandra-0:/mnt/vol_data/kanister-pvc
  2026-04-01 02:38:35 UTC k29bd7207096ae39ac... 67.2 MB dgrwxrwxrwx files:147 dirs:102 (latest-1)
```

Content stats:

```
Count: 197
Total Bytes: 6.5 MB
Total Packed: 178.9 KB (compression 97.2%)
```

Snapshot source pattern: `<user>@<cluster-id>.<namespace>.<pvc-name>:/mnt/vol_data/kanister-pvc`.

#### Cleanup

```bash
oc delete pod $KOPIA_POD -n kasten-io
```

Don't leave the debug pod running — it won't be backed up but wastes resources.

#### k10_repo_checker.sh Reference

| Flag | Value         | Description                                                             |
| ---- | ------------- | ----------------------------------------------------------------------- |
| `-r` | `application` | Repo type: `application`, `collections`, or `disaster_recovery`.        |
| `-o` | `connect`     | Operation: `connect`, `diagnose`, `upgrade_begin`, `upgrade_rollback`.  |
| `-a` | `cassandra`   | Application (namespace) name.                                           |
| `-p` | `s3-bucket1`  | Location profile name.                                                  |
| `-n` | `kasten-io`   | K10 namespace.                                                          |
| `-w` | (optional)    | Workload name if different from app name.                               |
| `-b` | (optional)    | Block-mode repos.                                                       |
| `-i` | (optional)    | Override image repo (default: `gcr.io/kasten-images`). For air-gapped.  |
| `-t` | (optional)    | Override image tag.                                                     |
| `-L` | (optional)    | Log levels: `k10_log_level`, `kopia_log_level`, `kopia_file_log_level`. |

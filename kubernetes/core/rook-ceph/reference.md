## Rook-Ceph Reference

Helm charts **rook-ceph v1.20.1** (operator) + **rook-ceph-cluster v1.20.1** (cluster).

---

### kubernetes/core/rook-ceph/cluster/helm-release.yml

```yaml
---
# yaml-language-server: $schema=https://chkpwd.github.io/iac/helm.toolkit.fluxcd.io/helmrelease_v2.json
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: rook-ceph-cluster
spec:
  interval: 1h
  timeout: 15m
  chart:
    spec:
      chart: rook-ceph-cluster
      version: v1.19.6
      sourceRef:
        kind: HelmRepository
        name: rook-ceph
  dependsOn:
    - name: rook-ceph-operator
      namespace: rook-ceph
  values:
    monitoring:
      enabled: true
      createPrometheusRules: true
      prometheusRuleOverrides:
        CephPGImbalance:
          disabled: true
        CephNodeDiskspaceWarning:
          disabled: true
    toolbox:
      enabled: true
    route:
      dashboard:
        host:
          name: rook.chkpwd.com
        parentRefs:
          - name: private
            namespace: networking
            sectionName: https
    cephClusterSpec:
      cephConfig:
        global:
          bdev_enable_discard: "true" # quote
          bdev_async_discard_threads: "1" # quote
          osd_class_update_on_start: "false" # quote
          device_failure_prediction_mode: local # requires mgr module
        mon:
          mon_data_avail_warn: "20" # quote
      cleanupPolicy:
        wipeDevicesFromOtherClusters: true
      crashCollector:
        disable: false
      csi:
        readAffinity:
          enabled: true
          crushLocationLabels: ["kubernetes.io/hostname"]
      dashboard:
        enabled: true
        urlPrefix: /
        ssl: false
        prometheusEndpoint: http://prometheus-operated.monitoring.svc.cluster.local:9090
      mgr:
        modules:
          - name: diskprediction_local
            enabled: true
          - name: insights
            enabled: true
          - name: pg_autoscaler
            enabled: true
          - name: rook
            enabled: true
      network:
        provider: host
        connections:
          requireMsgr2: true
      storage:
        useAllNodes: true
        useAllDevices: false
        deviceFilter: nvme0n1
        config:
          osdsPerDevice: "1"
      resources:
        mgr:
          limits:
            cpu: 500m
            memory: 900Mi
          requests:
            cpu: 50m
            memory: 320Mi
        mon:
          limits:
            cpu: 500m
            memory: 640Mi
          requests:
            cpu: 100m
            memory: 320Mi
        osd:
          limits:
            cpu: 500m
            memory: 1600Mi
          requests:
            cpu: 150m
            memory: 800Mi
        prepareosd:
          limits:
            cpu: 1000m
            memory: 400Mi
          requests:
            cpu: 50m
            memory: 200Mi
        mgr-sidecar:
          limits:
            cpu: 300m
            memory: 100Mi
          requests:
            cpu: 50m
            memory: 40Mi
        crashcollector:
          limits:
            cpu: 100m
            memory: 64M
          requests:
            cpu: 15m
            memory: 32M
        logcollector:
          limits:
            cpu: 50m
            memory: 32Mi
          requests:
            cpu: 5m
            memory: 16Mi
        cleanup:
          limits:
            cpu: 500m
            memory: 1Gi
          requests:
            cpu: 100m
            memory: 100Mi
    cephBlockPools:
      - name: ceph-blockpool
        spec:
          failureDomain: host
          replicated:
            size: 2
        storageClass:
          enabled: true
          name: ceph-block
          isDefault: true
          reclaimPolicy: Delete
          allowVolumeExpansion: true
          volumeBindingMode: Immediate
          mountOptions: ["discard"]
          parameters:
            imageFormat: "2"
            imageFeatures: layering,fast-diff,object-map,deep-flatten,exclusive-lock
            csi.storage.k8s.io/provisioner-secret-name: rook-csi-rbd-provisioner
            csi.storage.k8s.io/provisioner-secret-namespace: "{{ .Release.Namespace }}"
            csi.storage.k8s.io/controller-expand-secret-name: rook-csi-rbd-provisioner
            csi.storage.k8s.io/controller-expand-secret-namespace: "{{ .Release.Namespace }}"
            csi.storage.k8s.io/node-stage-secret-name: rook-csi-rbd-node
            csi.storage.k8s.io/node-stage-secret-namespace: "{{ .Release.Namespace }}"
            csi.storage.k8s.io/fstype: ext4
    cephBlockPoolsVolumeSnapshotClass:
      enabled: true
      name: csi-ceph-blockpool
      isDefault: false
      deletionPolicy: Delete
      allowVolumeExpansion: true
      volumeBindingMode: Immediate
      mountOptions: ["discard"]
    cephFileSystems: []
    cephObjectStores: []
```

### kubernetes/core/rook-ceph/external-secret.yml

```yaml
---
# yaml-language-server: $schema=https://chkpwd.github.io/iac/external-secrets.io/externalsecret_v1beta1.json
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: rook-ceph-dashboard
spec:
  refreshInterval: 3h
  secretStoreRef:
    name: bitwarden-secrets-manager
    kind: ClusterSecretStore
  target:
    name: rook-ceph-dashboard-password # rook-ceph expects this name
    template:
      data:
        password: "{{ .dashboard_password }}"
  dataFrom:
    - extract:
        key: "rook-ceph"
```

### kubernetes/core/rook-ceph/helm-release.yml

```yaml
---
# yaml-language-server: $schema=https://chkpwd.github.io/iac/helm.toolkit.fluxcd.io/helmrelease_v2.json
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: rook-ceph-operator
spec:
  interval: 1h
  timeout: 15m
  chart:
    spec:
      chart: rook-ceph
      version: v1.19.6
      sourceRef:
        kind: HelmRepository
        name: rook-ceph
  values:
    csi:
      cephFSKernelMountOptions: ms_mode=prefer-crc
      enableCephfsDriver: false
      enableCephfsSnapshotter: false
      enableLiveness: true
      serviceMonitor:
        enabled: true
      csiRBDProvisionerResource: |
        - name : csi-provisioner
          resource:
            requests:
              memory: 16Mi
              cpu: 5m
            limits:
              memory: 32Mi
              cpu: 100m
        - name : csi-resizer
          resource:
            requests:
              memory: 48Mi
              cpu: 5m
            limits:
              memory: 96Mi
              cpu: 100m
        - name : csi-attacher
          resource:
            requests:
              memory: 32Mi
              cpu: 5m
            limits:
              memory: 64Mi
              cpu: 100m
        - name : csi-snapshotter
          resource:
            requests:
              memory: 16Mi
              cpu: 5m
            limits:
              memory: 32Mi
              cpu: 100m
        - name : csi-rbdplugin
          resource:
            requests:
              memory: 48Mi
              cpu: 15m
            limits:
              memory: 192Mi
              cpu: 200m
        - name : liveness-prometheus
          resource:
            requests:
              memory: 24Mi
              cpu: 5m
            limits:
              memory: 48Mi
              cpu: 100m
      csiRBDPluginResource: |
        - name : driver-registrar
          resource:
            requests:
              memory: 64Mi
              cpu: 5m
            limits:
              memory: 128Mi
              cpu: 100m
        - name : csi-rbdplugin
          resource:
            requests:
              memory: 64Mi
              cpu: 10m
            limits:
              memory: 192Mi
              cpu: 200m
        - name : liveness-prometheus
          resource:
            requests:
              memory: 48Mi
              cpu: 5m
            limits:
              memory: 96Mi
              cpu: 100m
    cephCommandsTimeoutSeconds: "20"
    monitoring:
      enabled: true
      createPrometheusRules: true
    resources:
      requests:
        memory: 128Mi # unchangable
        cpu: 100m # unchangable
      limits: {}
```

### kubernetes/core/rook-ceph/source.yml

```yaml
---
# yaml-language-server: $schema=https://chkpwd.github.io/iac/source.toolkit.fluxcd.io/helmrepository_v1.json
apiVersion: source.toolkit.fluxcd.io/v1
kind: HelmRepository
metadata:
  name: rook-ceph
spec:
  interval: 2h
  url: https://charts.rook.io/release
```

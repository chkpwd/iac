```bash
# Apply Secret
cat <<EOF | k apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: bws-secrets
  namespace: security
  labels:
    external-secrets.io/type: webhook
stringData:
  token: <token>
EOF

# Apply CRDs
helmfile -f hacks/crds.yml template -q | kubectl apply --server-side --field-manager flux-client-side-apply -f -


# Apply Foundation
helmfile --file "hacks/helmfile.yml" apply --skip-diff-on-install --suppress-diff --suppress-secrets
```

## KCL

KCL sources live in `kcl/apps/*.k`.
Generated YAML under `kcl/apps/<name>/resources/` is build output.

Quick reference:

```bash
# Render one app
task kcl:build APP=bazarr

# Render all KCL apps
task kcl:build

# Verify generated YAML is in sync
task kcl:check
```

Do not edit generated YAML by hand. Edit `kcl/apps/<name>.k` and rebuild.

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

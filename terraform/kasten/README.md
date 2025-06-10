kubectl --namespace kasten-io create token auth-svc --duration=24h
kubectl get secret auth-token --namespace kasten-io -o json | yq -r '.data.token | map_values(@base64d)'

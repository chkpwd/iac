# Setup Dashboard Access

## 1. Create Service Account

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
name: k10-custom-sa
namespace: kasten-io
annotations:
eks.amazonaws.com/role-arn: arn:aws:iam::970547363121:role/kasten-staging-kasten-k10
EOF

## 2. Create ClusterRole for viewing deployments

cat <<EOF | kubectl apply -n kasten-io -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
name: k10-deployments-view
rules:

- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list", "watch"]
  EOF

## 3. Bind ClusterRole to the ServiceAccount within the kasten-io namespace

kubectl create rolebinding k10-custom-sa-deployments-view \
 --role=k10-deployments-view \
 --serviceaccount=kasten-io:k10-custom-sa \
 --namespace=kasten-io

## 4. Bind ClusterRole k10-admin to ServiceAccount cluster-wide

kubectl create clusterrolebinding k10-custom-sa-admin-binding \
 --clusterrole=k10-admin \
 --serviceaccount=kasten-io:k10-custom-sa

## 5. Generate a token valid for 24 hours

kubectl --namespace kasten-io create token k10-custom-sa --duration=24h

## Create secret

```yaml
cat <<EOF | k apply -f -
apiVersion: v1
kind: Secret
type: kubernetes.io/service-account-token
metadata:
  name: k10-custom-access-token
  annotations:
    kubernetes.io/service-account.name: "ka-custom-sa"
EOF
```

## Get long-lived token

kubectl get secret auth-token --namespace kasten-io -o json | yq -r '.data.token | map_values(@base64d)'

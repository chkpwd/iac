NAMESPACE="kube-system"

for i in cilium kube-vip; do 
  kubectl patch helmchart $i -n ${NAMESPACE} \
    --type=json -p='[{"op": "add", "path": "/metadata/annotations/helmcharts.helm.cattle.io~1unmanaged", "value": "true"}]'
  # Delete the HelmChart CR
  kubectl delete helmchart $i -n ${NAMESPACE} &
  # Force delete the HelmChart
  kubectl patch helmchart $i -n ${NAMESPACE} \
    --type=json -p='[{"op": "replace", "path": "/metadata/finalizers", "value": []}]';
done

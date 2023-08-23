#!/usr/bin/env bash

# the namespace of kubevirt installation
export namespace=kubevirt
export labels=("operator.kubevirt.io" "operator.cdi.kubevirt.io" "kubevirt.io" "cdi.kubevirt.io")
export namespaces=(default ${namespace} "<other-namespaces that has kubevirst resources>")

kubectl -n ${namespace} delete kv kubevirt
kubectl -n ${namespace} patch kv kubevirt --type=json -p '[{ "op": "remove", "path": "/metadata/finalizers" }]'
kubectl get vmis --all-namespaces -o=custom-columns=NAME:.metadata.name,NAMESPACE:.metadata.namespace,FINALIZERS:.metadata.finalizers --no-headers | grep foregroundDeleteVirtualMachine | while read p; do
    arr=($p)
    name="${arr[0]}"
    namespace="${arr[1]}"
    kubectl patch vmi $name -n $namespace --type=json -p '[{ "op": "remove", "path": "/metadata/finalizers" }]'
done

for i in ${namespaces[@]}; do
    for label in ${labels[@]}; do
        kubectl -n ${i} delete deployment -l ${label}
        kubectl -n ${i} delete ds -l ${label}
        kubectl -n ${i} delete rs -l ${label}
        kubectl -n ${i} delete pods -l ${label}
        kubectl -n ${i} delete services -l ${label}
        kubectl -n ${i} delete pvc -l ${label}
        kubectl -n ${i} delete rolebinding -l ${label}
        kubectl -n ${i} delete roles -l ${label}
        kubectl -n ${i} delete serviceaccounts -l ${label}
        kubectl -n ${i} delete configmaps -l ${label}
        kubectl -n ${i} delete secrets -l ${label}
        kubectl -n ${i} delete jobs -l ${label}
    done
done

for label in ${labels[@]}; do
    kubectl delete validatingwebhookconfiguration -l ${label}
    kubectl delete pv -l ${label}
    kubectl delete clusterrolebinding -l ${label}
    kubectl delete clusterroles -l ${label}
    kubectl delete customresourcedefinitions -l ${label}
    kubectl delete scc -l ${label}
    kubectl delete apiservices -l ${label}

    kubectl get apiservices -l ${label} -o=custom-columns=NAME:.metadata.name,FINALIZERS:.metadata.finalizers --no-headers | grep foregroundDeletion | while read p; do
        arr=($p)
        name="${arr[0]}"
        kubectl -n ${i} patch apiservices $name --type=json -p '[{ "op": "remove", "path": "/metadata/finalizers" }]'
    done
done
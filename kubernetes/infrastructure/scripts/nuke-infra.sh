#!/bin/bash

# An array of namespaces to ignore
declare -a ignore_namespaces=(
	"flux-system"
	"kube-system"
	"default"
	"kube-node-lease"
	"kube-public"
)

# Get all namespaces
namespaces=$(kubectl get ns -o jsonpath="{.items[*].metadata.name}")

# Loop through each namespace
for namespace in $namespaces; do
  # Check if the namespace should be ignored
  if [[ " ${ignore_namespaces[@]} " =~ " ${namespace} " ]]; then
    continue
  fi
  
  # Delete all resources in the namespace
  kubectl delete all --all --namespace "$namespace"
done

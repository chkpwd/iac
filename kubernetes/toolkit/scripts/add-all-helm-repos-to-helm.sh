#!/usr/bin/env bash

# Set working dir
WORKDIR="/home/hyoga/code/boilerplates/kubernetes/infrastructure"

# Change into kubernetes infra dir
cd $WORKDIR

for file in flux-system/sources/helm-repos/*.yaml; do
    name=$(yq -r '.metadata.name' $file);
    url=$(yq -r '.spec.url' $file);

    if [ "$name" != "null" ]; then
        helm repo add "$name" "$url";
    fi;
done;

helm repo update
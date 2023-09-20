#!/usr/bin/env bash

# Set working dir
WORKDIR="$HOME/code/iac/kubernetes/infra"

# Change into kubernetes infra dir
cd $WORKDIR

for file in sources/helm-repos/*.yaml; do
    name=$(yq -r '.metadata.name' $file);
    url=$(yq -r '.spec.url' $file);

    if [ "$name" != "null" ]; then
        helm repo add "$name" "$url";
    fi;
done;

helm repo update

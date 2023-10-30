#!/bin/bash

declare -a stateList=(
    # Example
    # vsphere_folder.windows_folder
)

for state in "${stateList[@]}"
do
    terraform state rm $state
done

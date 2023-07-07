#!/bin/bash

declare -a stateList=(
	
)

for state in "${stateList[@]}"
do
    echo "Removing $state from terraform state..."
    terraform state rm $state
done

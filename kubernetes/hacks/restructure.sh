#!/usr/bin/env bash

# Check if the relative path is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <relative_path>"
    exit 1
fi

# Define the relative path to the "app" subdirectory
relative_path="$1"

# Check if the "app" subdirectory exists within the given relative path
if [ ! -d "$relative_path/app" ]; then
    echo "Directory '$relative_path/app' does not exist!"
    exit 1
fi

# Move all files from the "app" subdirectory to the parent directory
mv "$relative_path/app"/* "$relative_path/"

# Check if the move was successful
if [ $? -ne 0 ]; then
    echo "Failed to move files from '$relative_path/app' to '$relative_path'."
    exit 1
fi

# Remove the now-empty "app" subdirectory
rmdir "$relative_path/app"

# Check if "ks.yml" exists and rename it to "flux-kustomization.yml"
if [ -f "$relative_path/ks.yml" ]; then
    mv "$relative_path/ks.yml" "$relative_path/flux-kustomization.yml"
    # Remove relative path from kustomize path field
    sed -i '' "s/\/app/\//g" "$relative_path/flux-kustomization.yml"
else
    echo "'ks.yml' does not exist in the directory, skipping rename."
fi

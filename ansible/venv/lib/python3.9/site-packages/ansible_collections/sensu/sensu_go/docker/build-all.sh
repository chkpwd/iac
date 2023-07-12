#!/bin/bash -eu

set -o pipefail

for f in *.docker
do
  ./build.sh "$f"
done

#!/bin/bash -eu

set -o pipefail

readonly filename="$1"; shift

readonly base=${filename%.docker}
readonly name=${base%-*}
readonly version=${base##*-}
readonly tag="quay.io/xlab-steampunk/sensu-go-tests-$name:$version"

docker build --pull -f "$filename" -t "$tag" .
docker push "$tag"

#!/bin/bash -ex

docker run \
  --rm \
  --volume "${PWD}/CHANGELOG.md":/CHANGELOG.md \
  cyberark/parse-a-changelog
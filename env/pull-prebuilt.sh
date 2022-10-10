#!/usr/bin/env bash

set -eu
set -o pipefail
cd $(dirname $0)
source config.sh

docker pull $PREBUILT_PULL_NAME
docker tag $PREBUILT_PULL_NAME $PREBUILT_IMAGE_NAME
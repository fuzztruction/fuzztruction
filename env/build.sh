#!/usr/bin/env bash

set -eu
set -o pipefail
cd $(dirname $0)

source config.sh
cd ..

log_success "[+] Building docker image"
docker build --build-arg USER_UID="$(id -u)" --build-arg USER_GID="$(id -g)" --target dev $@ -t $IMAGE_NAME .
if [[ $?  -ne 0 ]]; then
    log_error "[+] Error while building the docker image."
    exit 1
else
    log_success "[+] Docker image successfully build. Use ./env/start.sh and ./env/stop.sh to manage the containers lifecycle."
fi

exit 0

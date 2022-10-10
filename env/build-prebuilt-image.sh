#!/usr/bin/env bash

set -eu

sudo apt install -y jq textdraw rsync

cd $(dirname $0)
source config.sh

container="$(docker ps --filter="name=$CONTAINER_NAME" --latest --quiet)"
if [[ -z "$container" ]]; then
    log_error "[!] The container $CONTAINER_NAME must be running."
    exit 1
fi

log_success "[+] Found running container $container"
log_success "[+] Committing container into new image. This may take a while."

cmd="docker commit $container $PREBUILT_IMAGE_NAME"
log_success "[+] Running $cmd"
sleep 2
committed_id=$($cmd)

# Copy working directory
host_dir=$(docker inspect $container | jq '.[0].HostConfig.Binds' | grep ":/home/user/fuzztruction\"" | cut -d ':' -f 1 | tr -d '"' | xargs)
if [[ ! -d "$host_dir" ]]; then
    log_error "[!] Invalid host workdir \"$host_dir\""
    exit 1
fi

readonly prebuilt_workdir_dst=./prebuilt-workdir
function cleanup {
    log_success "[+] Deleting $prebuilt_workdir_dst"
    rm -rf $prebuilt_workdir_dst
}
cleanup
trap cleanup EXIT
mkdir -p "$prebuilt_workdir_dst"


log_success "[+] Copying directory $host_dir to $prebuilt_workdir_dst"
cmd="rsync -av --progress --delete
    --exclude data/
    --exclude **/.git
    --exclude .gitmodules
    --exclude .gitignore
    --exclude Dockerfile
    --exclude .dockerignore
    --exclude eval-results
    --exclude .mypy_cache
    --exclude env/
    --exclude fuzztruction-experiments/comparison-with-state-of-the-art/scripts/logs
    "$host_dir/"
    "$prebuilt_workdir_dst"
    "
log_success "[+] $cmd"
sleep 2s
$cmd

log_success "[+] Building prebuilt image"
cmd="docker build
    --build-arg WORKDIR_PATH=$prebuilt_workdir_dst
    --build-arg BASE_IMAGE=$committed_id
    -t $PREBUILT_IMAGE_NAME
    -f ./Dockerfile-Prebuilt
    .
    "
log_success "[+] $cmd"
sleep 2s
$cmd

# Push Docker image to the given URL if set.
if [[ ! -z "$PREBUILT_PUSH_URL" ]]; then
    docker tag $PREBUILT_IMAGE_NAME $PREBUILT_PUSH_URL
    cmd="docker push $PREBUILT_PUSH_URL"
    echo "[+] Running $cmd"
    $cmd
fi

#!/bin/bash
set -e

PV_DOCKER_REGISTRY="polyverse/exp-nginx-1.4.0-brop"

main() {
        GIT_COMMIT=$(git rev-parse --verify HEAD)

	docker build --build-arg PV_FROM=ubuntu:xenial -t "$PV_EXP_NAME" -t "$PV_DOCKER_REGISTRY:latest" -t "$PV_DOCKER_REGISTRY:$GIT_COMMIT" .
        [ $? -ne 0 ] && return 1

	return 0
}

main "$@"
exit $?

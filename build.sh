#!/bin/bash
set -e

PV_DOCKER_REGISTRY="507760724064.dkr.ecr.us-west-2.amazonaws.com"
PV_EXP_NAME="exp-nginx-1.4.0-brop"

main() {
        GIT_COMMIT=$(git rev-parse --verify HEAD)

	docker build --build-arg PV_FROM=ubuntu:xenial -t "$PV_EXP_NAME" -t "$PV_DOCKER_REGISTRY/$PV_EXP_NAME:latest" -t "$PV_DOCKER_REGISTRY/$PV_EXP_NAME:$GIT_COMMIT" .
        [ $? -ne 0 ] && return 1

	return 0
}

main "$@"
exit $?

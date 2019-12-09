#!/bin/bash
set -e

PV_DOCKER_REGISTRY="507760724064.dkr.ecr.us-west-2.amazonaws.com"
PV_EXP_NAME="exp-nginx-1.4.0-brop"

main() {
        GIT_COMMIT=$(git rev-parse --verify HEAD)

	docker build --build-arg PV_FROM=i386/ubuntu:trusty -t "$PV_EXP_NAME-32" -t "$PV_DOCKER_REGISTRY/$PV_EXP_NAME-32:latest" -t "$PV_DOCKER_REGISTRY/$PV_EXP_NAME-32:$GIT_COMMIT" .
        [ $? -ne 0 ] && return 1

	docker build --build-arg PV_FROM=ubuntu:trusty -t "$PV_EXP_NAME-64" -t "$PV_DOCKER_REGISTRY/$PV_EXP_NAME-64:latest" -t "$PV_DOCKER_REGISTRY/$PV_EXP_NAME-64:$GIT_COMMIT" .
        [ $? -ne 0 ] && return 1

	return 0
}

main "$@"
exit $?

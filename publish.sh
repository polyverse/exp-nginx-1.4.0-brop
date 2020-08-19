#!/bin/bash
set -e

PV_DOCKER_REGISTRY="polyverse/exp-nginx-1.4.0-brop"

main() {
        GIT_COMMIT=$(git rev-parse --verify HEAD)

        docker push "$PV_DOCKER_REGISTRY:latest"
        [ $? -ne 0 ] && return 1
        docker push "$PV_DOCKER_REGISTRY:$GIT_COMMIT"
        [ $? -ne 0 ] && return 1

        return 0
}

main "$@"
exit $?

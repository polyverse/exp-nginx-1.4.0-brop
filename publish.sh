#!/bin/bash
set -e

PV_DOCKER_REGISTRY="507760724064.dkr.ecr.us-west-2.amazonaws.com"
PV_EXP_NAME="exp-nginx-1.4.0-brop"

main() {
        aws --region us-west-2 ecr get-login --no-include-email | bash -s
        [ $? -ne 0 ] && return 1

        GIT_COMMIT=$(git rev-parse --verify HEAD)

        # create the repo; no harm if it already exists other than the call returns 255⏎
        aws --region us-west-2 ecr create-repository --repository-name $PV_EXP_NAME-32 || true
        aws --region us-west-2 ecr create-repository --repository-name $PV_EXP_NAME-64 || true

        docker push "$PV_DOCKER_REGISTRY/$PV_EXP_NAME-32:latest"
        docker push "$PV_DOCKER_REGISTRY/$PV_EXP_NAME-32:$GIT_COMMIT"
        [ $? -ne 0 ] && return 1

        docker push "$PV_DOCKER_REGISTRY/$PV_EXP_NAME-64:latest"
        docker push "$PV_DOCKER_REGISTRY/$PV_EXP_NAME-64:$GIT_COMMIT"
        [ $? -ne 0 ] && return 1

        return 0
}

main "$@"
exit $?

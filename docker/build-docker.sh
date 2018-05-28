#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR/..

DOCKER_IMAGE=${DOCKER_IMAGE:-monacocoin-net/monoeci-cored-develop}
DOCKER_TAG=${DOCKER_TAG:-latest}

BUILD_DIR=${BUILD_DIR:-.}

rm docker/bin/*
mkdir docker/bin
cp $BUILD_DIR/src/monoecid docker/bin/
cp $BUILD_DIR/src/monoeci-cli docker/bin/
cp $BUILD_DIR/src/monoeci-tx docker/bin/
strip docker/bin/monoecid
strip docker/bin/monoeci-cli
strip docker/bin/monoeci-tx

docker build --pull -t $DOCKER_IMAGE:$DOCKER_TAG -f docker/Dockerfile docker

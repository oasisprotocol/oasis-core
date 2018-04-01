#!/bin/bash

DATA_PATH="/tmp/tendermint"
GENESIS_PATH=$DATA_PATH/genesis.json
IMAGE_TAG=tendermint/tendermint:0.13.0

# Check to see if docker is on the path
if [ ! $(which docker) ]; then
    echo "Please install docker"
    exit 1
fi

# Clear the data directory
if [ -f $GENESIS_PATH ]; then
    echo "Clearing Tendermint directory"
    docker run -it --rm -v "$DATA_PATH:/tendermint" $IMAGE_TAG unsafe_reset_all
else
    echo "Cannot recognize Tendermint directory"
fi


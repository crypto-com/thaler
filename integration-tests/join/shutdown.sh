#!/bin/bash

export CURRENT_HASH=$(git rev-parse HEAD)
echo "shutdown CURRENT_HASH=" $CURRENT_HASH
docker-compose -p $CURRENT_HASH down

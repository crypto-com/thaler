#!/bin/bash
echo "compile binaries"
cd ./compile


export CURRENT_HASH=$(git rev-parse HEAD)
echo "compile CURRENT_HASH=" $CURRENT_HASH
docker-compose -p $CURRENT_HASH up
cd ..

#!/bin/bash
docker run -p 1022:22 -v $(pwd)/disk:/root/disk --rm -it  chain_test /bin/bash

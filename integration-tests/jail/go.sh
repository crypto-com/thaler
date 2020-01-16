#!/bin/bash
docker run --rm -it -v $PWD/disk:/root/disk -v /nix:/nix -v /opt/intel:/opt/intel -v $HOME/Github:/root/Github --device /dev/isgx my

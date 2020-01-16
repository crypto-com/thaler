#!/bin/bash
./run_jail.sh
ret=$?
if [ $ret -ne 0 ]; then
    echo "jail test fail"
    exit -1
fi

./run_join.sh
ret=$?
if [ $ret -ne 0 ]; then
    echo "join test fail"
    exit -1
fi

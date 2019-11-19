#!/bin/bash
docker-compose up -d --build
echo "docker compose ok"
#echo "wait for docker setting up"
#sleep 1800
#echo "done"
pip3 install docker
python3 ./disk/jail_test.py
echo "test finished"
sleep 4
docker-compose down
echo "OK"
sleep 2

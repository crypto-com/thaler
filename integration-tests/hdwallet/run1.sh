#!/bin/bash
#docker-compose up -d
#docker-compose up 
#echo "wait for docker setting up"
#sleep 600
#sleep 300
echo "done"
python3 ./disk/test.py
echo "test finished"
sleep 4
docker-compose down
echo "OK"
sleep 2

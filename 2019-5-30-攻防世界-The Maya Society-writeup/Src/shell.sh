#!/bin/bash
CURR_TIME=1325347200
LAST_TIME=1356969600
export CURR_TIME
while [ $CURR_TIME -lt $LAST_TIME ]
do
    value=$(CURR_TIME=$CURR_TIME LD_PRELOAD=$(pwd)/faketime.so ./launcher)
    if [ "$value" != "" ]
    then
        echo $value
        exit 1
    else
        CURR_TIME=$[CURR_TIME+1]
    fi
done

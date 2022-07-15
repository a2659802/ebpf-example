#!/bin/bash

function nsenter-ctn () {
    CTN=$1 # Container ID or name
    PID=$(sudo docker inspect --format "{{.State.Pid}}" $CTN)
    shift 1 # Remove the first arguement, shift remaining ones to the left
    sudo nsenter -t $PID $@
}

docke kill ctn2
docker rm ctn2
docker run -d --name ctn2  nginx:alpine

nsenter-ctn ctn2 -n tc qdisc add dev eth0 clsact
nsenter-ctn ctn2 -n tc filter add dev eth0 ingress bpf da obj bpf_bpfel.o sec tc
cat /sys/kernel/debug/tracing/trace_pipe

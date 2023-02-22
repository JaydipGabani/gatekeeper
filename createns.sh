#!/bin/bash
case $1 in
    c)
        for i in $(seq 1001 1 $2)
        do
            kubectl create ns test-$i 
            kubectl label ns test-$i test=true
        done
    ;;
    d)
        kubectl delete ns -l="test=true"
    ;;
    *)
    ;;
esac
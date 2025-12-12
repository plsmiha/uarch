#!/bin/bash

killall attack 2>/dev/null
killall leak_hash 2>/dev/null
killall call_rdrand 2>/dev/null

make all
make call_rdrand

echo
echo "Running prefix attack..."

taskset -c 1,5 ./attack & (sleep 2 && taskset -c 3 ./call_rdrand)

make clean > /dev/null

rm call_rdrand
killall call_rdrand 2>/dev/null

#!/bin/bash

# Cleanup function
cleanup() {
    echo ""
    echo "killing processes..."
    kill -9 $RDRAND_PID $CROSSTALK_PID 2>/dev/null
    pkill -9 call_rdrand crosstalk 2>/dev/null
    wait 2>/dev/null
    make clean
    exit 0
}

# Trap Ctrl+C
trap cleanup SIGINT SIGTERM

make
taskset -c 3 ./call_rdrand &
RDRAND_PID=$!
sleep 0.5 
taskset -c 1,5 ./crosstalk &
CROSSTALK_PID=$!

echo "Press Ctrl+C to stop"

# Wait forever (until Ctrl+C)
wait


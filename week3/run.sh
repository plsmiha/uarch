#!/bin/bash

# Cleanup function
cleanup() {
    echo ""
    echo "killing processes..."
    kill -9 $ATTACK_PID 2>/dev/null
    pkill -9 attack 2>/dev/null
    wait 2>/dev/null
    make clean
    exit 0
}

# Trap Ctrl+C
trap cleanup SIGINT SIGTERM

killall attack 2>/dev/null

sleep 1

make
taskset -c 1,5 ./attack &
ATTACK_PID=$!
sleep 1.0
taskset -c 3 /tmp/set_root_password

echo "Press Ctrl+C to stop"

#taskset -c 0,4 ./leak_hash


# Wait forever (until Ctrl+C)
wait


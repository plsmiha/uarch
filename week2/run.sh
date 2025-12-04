#!/bin/bash

# Simple FPVI test script

echo "Running FPVI attack..."
./fpvi > output.txt

# Extract operands
DX=$(grep "dx = " output.txt | cut -d' ' -f3)
DY=$(grep "dy = " output.txt | cut -d' ' -f3)

echo "Testing with ground truth..."
/tmp/test_operands $DX $DY

echo ""
echo "Your result:"
grep "TRANSIENT LEAKED RESULT" output.txt

echo ""
echo "Compare with trans_res above ^^"
#!/bin/bash

# Simple FPVI test script

echo "Running FPVI attack..."
./fpvi > output.txt

# Extract operands
DX=$(grep "dx = " output.txt | cut -d' ' -f3)
DY=$(grep "dy = " output.txt | cut -d' ' -f3)

echo "Testing with ground truth..."
/tmp/test_operands $DX $DY > ground_truth.txt

# Extract results
YOUR_RESULT=$(grep "TRANSIENT LEAKED RESULT" output.txt | cut -d' ' -f4)
GROUND_TRUTH=$(grep "trans_res" ground_truth.txt | grep -o "0x[0-9a-f]*" | head -1)

echo ""
echo "=== COMPARISON ==="
echo "Your result:    $YOUR_RESULT"
echo "Ground truth:   $GROUND_TRUTH"

if [ "$YOUR_RESULT" = "$GROUND_TRUTH" ]; then
    echo "PERFECT MATCH!"
else
    echo "DIFFERENT! "
fi
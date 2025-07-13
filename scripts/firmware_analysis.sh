#!/bin/bash
# Usage: ./firmware_analysis.sh firmware.bin

FIRMWARE=$1
if [ ! -f "$FIRMWARE" ]; then
  echo "Firmware file not found!"
  exit 1
fi

echo "Extracting strings from $FIRMWARE..."
strings "$FIRMWARE" > firmware_strings.txt

echo "Searching for potential credentials and backdoors..."
grep -iE 'password|user|admin|root|login|pass' firmware_strings.txt > suspicious_strings.txt

echo "Analysis complete."
echo "Check suspicious_strings.txt for potential sensitive info."

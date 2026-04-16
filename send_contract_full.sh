#!/bin/bash
# Send full contract to RAXC API and download the report

echo "[*] Sending contract to RAXC API at http://localhost:8080/analyze..."

RESPONSE=$(curl -s -X POST http://localhost:8080/analyze \
  -H "Content-Type: application/json" \
  -d @temp_contract.json)

echo "[*] Response: $RESPONSE"

# Extract download_url from JSON response
DOWNLOAD_URL=$(echo "$RESPONSE" | grep -o '"download_url":"[^"]*"' | sed 's/"download_url":"\(.*\)"/\1/')

if [ -n "$DOWNLOAD_URL" ]; then
  echo "[*] Report available at: $DOWNLOAD_URL"
  FILENAME=$(basename "$DOWNLOAD_URL")
  
  echo "[*] Downloading report to reports/$FILENAME..."
  curl -s "http://localhost:8080$DOWNLOAD_URL" > "reports/$FILENAME"
  
  echo "[✓] Report saved to reports/$FILENAME"
  echo ""
  echo "View report:"
  echo "  cat reports/$FILENAME"
  echo "  open reports/$FILENAME    # macOS"
else
  echo "[!] No download URL found in response"
  exit 1
fi

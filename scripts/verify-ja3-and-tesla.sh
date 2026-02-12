#!/usr/bin/env bash
# Verify Chrome JA3 impersonation and run Tesla experiments.
# Run from repo root: ./scripts/verify-ja3-and-tesla.sh
# Requires: httpx binary (go build -o httpx ./cmd/httpx/), jq

set -e
BIN="${BIN:-./httpx}"
if ! command -v jq &>/dev/null; then
  echo "jq required for JA3 parsing. Install or set BIN to your httpx path."
  exit 1
fi

echo "=== 1. JA3 verification (tls.peet.ws) ==="
echo "With -tls-impersonate-chrome:"
echo "https://tls.peet.ws/api/clean" | $BIN -tls-impersonate-chrome -silent -no-color -json -irr 2>/dev/null | head -1 | jq -r '.body' | jq -r '"  ja3: \(.ja3)\n  ja3_hash: \(.ja3_hash)"'

echo "Without impersonation (default Go):"
echo "https://tls.peet.ws/api/clean" | $BIN -silent -no-color -json -irr 2>/dev/null | head -1 | jq -r '.body' | jq -r '"  ja3: \(.ja3)\n  ja3_hash: \(.ja3_hash)"'
echo "If the two ja3_hash values differ, Chrome JA3 impersonation is active."
echo ""

echo "=== 2. Tesla experiments (www.tesla.com) ==="
CHROME_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

echo "2a. No TLS impersonation (default Go client):"
echo "www.tesla.com" | $BIN -title -sc -silent -no-color 2>/dev/null || true

echo "2b. Chrome JA3 only (random User-Agent):"
echo "www.tesla.com" | $BIN -tls-impersonate-chrome -title -sc -silent -no-color 2>/dev/null || true

echo "2c. Chrome User-Agent only (no JA3):"
echo "www.tesla.com" | $BIN -title -sc -silent -no-color -H "User-Agent: $CHROME_UA" 2>/dev/null || true

echo "2d. Chrome JA3 + Chrome User-Agent:"
echo "www.tesla.com" | $BIN -tls-impersonate-chrome -title -sc -silent -no-color -H "User-Agent: $CHROME_UA" 2>/dev/null || true

echo ""
echo "Done. Tesla uses Akamai WAF; 403 can be due to JA3, headers, IP, or other signals."
echo "Try -tls-impersonate-chrome with -browser-headers for Accept/Accept-Encoding."

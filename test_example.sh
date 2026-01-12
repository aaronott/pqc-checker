#!/bin/bash
# Example script to test multiple domains for PQC support

echo "Testing multiple domains for PQC support..."
echo ""

domains=(
    "google.com"
    "cloudflare.com"
    "github.com"
)

for domain in "${domains[@]}"; do
    echo "Testing $domain..."
    ./pqc_checker.py "$domain"
    echo ""
    echo "---"
    echo ""
done

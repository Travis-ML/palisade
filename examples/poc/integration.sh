set -euo pipefail   # poc/integration.sh: which connectors produced real data on day one?
for src in siem edr idp email cloud ticketing ti; do
  n=$(curl -s -H "Authorization: Bearer $POC_TOKEN" "$PRODUCT_API/connectors/$src/events?since=24h" | jq '.events | length')
  printf "%-10s events_last_24h=%s\n" "$src" "$n"
done

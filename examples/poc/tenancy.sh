set -euo pipefail   # poc/tenancy.sh: cross-tenant bleed check
CANARY="PALISADE-CANARY-7f3a9c"
curl -s -H "Authorization: Bearer $TENANT_B_TOKEN" "$PRODUCT_API/search?q=$CANARY" | grep -q "$CANARY" && echo "FAIL: canary visible from tenant B"

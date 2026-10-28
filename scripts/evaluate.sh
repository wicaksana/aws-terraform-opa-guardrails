#!/usr/bin/env bash
# Evaluate a Terraform plan (JSON) against the guardrails with `opa eval`.
#
#   scripts/evaluate.sh <plan.json> [decision.json]
#
# Prints a Markdown report, writes the decision document, and exits:
#   0  plan allowed
#   1  plan denied by one or more rules
#   2  evaluation failed (bad input, policy error); see stderr
# The Application Registry is called at $APPID_SERVICE_URL (falls back to the
# default in policies/guardrails.rego).
set -euo pipefail

PLAN="${1:?usage: $0 <plan.json> [decision.json]}"
OUT="${2:-decision.json}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if ! opa eval --data "$ROOT/policies/" --input "$PLAN" \
  --format raw --fail 'data.terraform.guardrails.decision' >"$OUT"; then
  echo "### Policy decision: ⚠️ ERROR (opa eval failed, see job log)"
  exit 2
fi

jq -r '
  "### Policy decision: \(if .allow then "✅ ALLOWED" else "❌ DENIED (\(.violations) violations)" end)",
  (if .violations > 0 then
     "", "| Rule | Resource | Message |", "|---|---|---|",
     (.deny | sort_by(.rule, .resource)[] | "| \(.rule) | `\(.resource)` | \(.message) |")
   else empty end)
' "$OUT"

jq -e '.allow' "$OUT" >/dev/null || exit 1

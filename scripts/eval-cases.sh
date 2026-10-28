#!/usr/bin/env bash
# `opa eval` regression tests for policies/terraform/guardrails/guardrails.rego:
#   tests/compliant/*.json     must produce no violations
#   tests/noncompliant/*.json  must only violate the rule in the file name
#                              (e.g. tag-002-*.json -> TAG-002)
# TAG-002 calls appid-service, so it must be reachable at the policy's
# appid_service_url.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
failures=0

appid_service_url="$(opa eval -d "$ROOT/policies/" -f raw 'data.terraform.guardrails.appid_service_url')"
curl -fsS "${appid_service_url%/}/healthz" >/dev/null || {
  echo "appid-service not reachable at $appid_service_url" >&2
  exit 2
}

for plan in "$ROOT"/tests/compliant/*.json "$ROOT"/tests/noncompliant/*.json; do
  name="$(basename "$(dirname "$plan")")/$(basename "$plan")"

  if [[ "$plan" == */compliant/* ]]; then
    expected="[]"
  else
    rule="$(basename "$plan" | cut -d- -f1,2 | tr '[:lower:]' '[:upper:]')"
    expected="[\"$rule\"]"
  fi

  # Each deny message starts with its rule ID, e.g. "TAG-002: ...".
  actual="$(opa eval -d "$ROOT/policies/" -i "$plan" -f raw 'data.terraform.guardrails.deny' |
    jq -c '[.[] | split(":")[0]] | unique')"

  if [[ "$actual" == "$expected" ]]; then
    echo "PASS  $name  $actual"
  else
    printf 'FAIL  %s\n  expected: %s\n  actual:   %s\n' "$name" "$expected" "$actual"
    failures=$((failures + 1))
  fi
done

exit "$failures"

package terraform.guardrails_test

import data.terraform.guardrails

# ---------------------------------------------------------------------------
# Fixtures: one compliant bucket with its public access block and SSE config
# ---------------------------------------------------------------------------

good_tags := {
	"ApplicationID": "APP-00001",
	"Environment": "dev",
	"Owner": "platform-team",
	"CostCenter": "CC-1234",
	"ManagedBy": "terraform",
}

change(type, actions, before, after) := {
	"address": sprintf("%s.this", [type]),
	"type": type,
	"name": "this",
	"change": {"actions": actions, "before": before, "after": after},
}

bucket_config(type) := {
	"type": type,
	"name": "this",
	"expressions": {"bucket": {"references": ["aws_s3_bucket.this.id", "aws_s3_bucket.this"]}},
}

plan := {
	"resource_changes": [
		change("aws_s3_bucket", ["create"], null, {"tags": null, "tags_all": good_tags}),
		change("aws_s3_bucket_public_access_block", ["create"], null, {
			"block_public_acls": true,
			"block_public_policy": true,
			"ignore_public_acls": true,
			"restrict_public_buckets": true,
		}),
		change("aws_s3_bucket_server_side_encryption_configuration", ["create"], null, {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}]}),
	],
	"configuration": {"root_module": {"resources": [
		bucket_config("aws_s3_bucket_public_access_block"),
		bucket_config("aws_s3_bucket_server_side_encryption_configuration"),
	]}},
}

patched(ops) := json.patch(plan, ops)

# ---------------------------------------------------------------------------
# Registry mocks for http.send
# ---------------------------------------------------------------------------

registry_valid(_) := {"status_code": 200, "body": {"valid": true}}

registry_invalid(_) := {"status_code": 200, "body": {"valid": false}}

registry_down(_) := {"status_code": 0}

# A 200 that is not the expected JSON (e.g. a misconfigured mock endpoint).
registry_unexpected(_) := {"status_code": 200, "raw_body": "nothing is configured"}

# Only accepts the request when the bearer token is sent.
registry_with_auth(req) := {"status_code": 200, "body": {"valid": true}} if {
	req.headers.Authorization == "Bearer s3cret"
} else := {"status_code": 401, "body": {"error": "unauthorized"}}

# ---------------------------------------------------------------------------
# Compliant plans
# ---------------------------------------------------------------------------

test_compliant_plan_is_allowed if {
	d := guardrails.decision with input as plan with http.send as registry_valid
	d == {"allow": true, "violations": 0, "deny": []}
}

test_resource_level_tags_are_used_when_tags_all_is_null if {
	p := patched([
		{"op": "replace", "path": "/resource_changes/0/change/after/tags_all", "value": null},
		{"op": "replace", "path": "/resource_changes/0/change/after/tags", "value": good_tags},
	])
	count(guardrails.deny) == 0 with input as p with http.send as registry_valid
}

test_prod_bucket_update_in_place_is_allowed if {
	prod_tags := object.union(good_tags, {"Environment": "prod"})
	p := patched([
		{"op": "replace", "path": "/resource_changes/0/change/actions", "value": ["update"]},
		{"op": "replace", "path": "/resource_changes/0/change/before", "value": {"tags_all": prod_tags}},
		{"op": "replace", "path": "/resource_changes/0/change/after/tags_all", "value": prod_tags},
	])
	count(guardrails.deny) == 0 with input as p with http.send as registry_valid
}

# ---------------------------------------------------------------------------
# TAG-001
# ---------------------------------------------------------------------------

test_missing_tags_are_denied if {
	p := patched([
		{"op": "remove", "path": "/resource_changes/0/change/after/tags_all/Owner"},
		{"op": "remove", "path": "/resource_changes/0/change/after/tags_all/CostCenter"},
	])
	denies := guardrails.deny with input as p with http.send as registry_valid
	denies == {`TAG-001: aws_s3_bucket.this is missing required tags: ["CostCenter", "Owner"]`}
}

test_invalid_environment_is_denied if {
	p := patched([{"op": "replace", "path": "/resource_changes/0/change/after/tags_all/Environment", "value": "staging"}])
	denies := guardrails.deny with input as p with http.send as registry_valid
	denies == {`TAG-001: aws_s3_bucket.this has Environment="staging"; must be one of ["dev", "prod", "stg"]`}
}

# ---------------------------------------------------------------------------
# TAG-002
# ---------------------------------------------------------------------------

test_malformed_application_id_is_denied_without_lookup if {
	p := patched([{"op": "replace", "path": "/resource_changes/0/change/after/tags_all/ApplicationID", "value": "APP-1"}])

	# registry_down would add a second message if the ID were looked up.
	denies := guardrails.deny with input as p with http.send as registry_down
	denies == {`TAG-002: aws_s3_bucket.this has ApplicationID="APP-1"; expected format APP-NNNNN (e.g. APP-00001)`}
}

test_unregistered_application_id_is_denied if {
	denies := guardrails.deny with input as plan with http.send as registry_invalid
	denies == {`TAG-002: aws_s3_bucket.this has ApplicationID="APP-00001", which is not registered in appid-service`}
}

test_unexpected_registry_response_fails_closed if {
	denies := guardrails.deny with input as plan with http.send as registry_unexpected
	denies == {`TAG-002: aws_s3_bucket.this has ApplicationID="APP-00001", which is not registered in appid-service`}
}

test_unreachable_registry_is_denied if {
	denies := guardrails.deny with input as plan
		with http.send as registry_down
		with opa.runtime as {"env": {"APPID_SERVICE_URL": "http://registry:8080/"}}
	denies == {`TAG-002: aws_s3_bucket.this ApplicationID="APP-00001" could not be verified; appid-service at http://registry:8080 returned HTTP 0 (0 = unreachable)`}
}

test_bearer_token_is_sent_when_configured if {
	count(guardrails.deny) == 0 with input as plan
		with http.send as registry_with_auth
		with opa.runtime as {"env": {"APPID_SERVICE_TOKEN": "s3cret"}}
}

test_missing_token_is_rejected_by_registry if {
	denies := guardrails.deny with input as plan
		with http.send as registry_with_auth
		with opa.runtime as {"env": {}}
	some msg in denies
	contains(msg, "returned HTTP 401")
}

# ---------------------------------------------------------------------------
# S3-001 / S3-002
# ---------------------------------------------------------------------------

test_public_access_block_flag_disabled_is_denied if {
	p := patched([{"op": "replace", "path": "/resource_changes/1/change/after/block_public_policy", "value": false}])
	denies := guardrails.deny with input as p with http.send as registry_valid
	some msg in denies
	startswith(msg, "S3-001: aws_s3_bucket.this needs an aws_s3_bucket_public_access_block")
	count(denies) == 1
}

test_public_access_block_missing_is_denied if {
	p := patched([
		{"op": "remove", "path": "/resource_changes/1"},
		{"op": "remove", "path": "/configuration/root_module/resources/0"},
	])
	denies := guardrails.deny with input as p with http.send as registry_valid
	some msg in denies
	startswith(msg, "S3-001: aws_s3_bucket.this")
	count(denies) == 1
}

test_sse_not_kms_is_denied if {
	p := patched([{
		"op": "replace",
		"path": "/resource_changes/2/change/after/rule/0/apply_server_side_encryption_by_default/0/sse_algorithm",
		"value": "AES256",
	}])
	denies := guardrails.deny with input as p with http.send as registry_valid
	denies == {`S3-002: aws_s3_bucket.this needs an aws_s3_bucket_server_side_encryption_configuration with sse_algorithm = "aws:kms"`}
}

# ---------------------------------------------------------------------------
# CHG-001
# ---------------------------------------------------------------------------

test_prod_bucket_replace_is_denied if {
	p := patched([
		{"op": "replace", "path": "/resource_changes/0/change/actions", "value": ["delete", "create"]},
		{"op": "replace", "path": "/resource_changes/0/change/before", "value": {"tags_all": {"Environment": "prod"}}},
	])
	denies := guardrails.deny with input as p with http.send as registry_valid
	denies == {`CHG-001: aws_s3_bucket.this is tagged Environment=prod and must not be deleted or replaced (actions: ["delete", "create"])`}
}

# ---------------------------------------------------------------------------
# Decision document
# ---------------------------------------------------------------------------

test_decision_splits_violations_into_fields if {
	d := guardrails.decision with input as plan with http.send as registry_invalid
	d.allow == false
	d.violations == 1
	d.deny == [{
		"rule": "TAG-002",
		"resource": "aws_s3_bucket.this",
		"message": `has ApplicationID="APP-00001", which is not registered in appid-service`,
	}]
}

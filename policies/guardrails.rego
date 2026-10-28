package terraform.guardrails

required_tags := {"ApplicationID", "Environment", "Owner", "CostCenter", "ManagedBy"}

allowed_environments := {"dev", "stg", "prod"}

# Override with the APPID_SERVICE_URL environment variable (e.g. in CI).
appid_service_url := trim_suffix(object.get(opa.runtime().env, "APPID_SERVICE_URL", "https://muarwi.free.beeceptor.com"), "/")

# Sent as a bearer token when the APPID_SERVICE_TOKEN environment variable is set.
appid_service_token := object.get(opa.runtime().env, "APPID_SERVICE_TOKEN", "")

public_access_flags := {"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Resources that will exist after apply (created, updated or unchanged).
planned_resources contains rc if {
	some rc in input.resource_changes
	not "delete" in rc.change.actions
}

planned_resources contains rc if {
	some rc in input.resource_changes
	"create" in rc.change.actions # replacement: delete + create
}

# Taggable resources expose a tags_all attribute.
taggable_resources contains rc if {
	some rc in planned_resources
	"tags_all" in object.keys(rc.change.after)
}

buckets contains rc if {
	some rc in planned_resources
	rc.type == "aws_s3_bucket"
}

# Effective tags: provider default_tags (tags_all) merged with resource tags.
tags(rc) := object.union(as_object(object.get(rc.change.after, "tags_all", null)), as_object(object.get(rc.change.after, "tags", null)))

as_object(x) := x if is_object(x)

else := {}

# Configuration block for a resource change (handles count/for_each indexes).
config(rc) := r if {
	some r in input.configuration.root_module.resources
	r.type == rc.type
	r.name == rc.name
}

# True if a resource change's `bucket` argument references the given bucket.
references_bucket(rc, bucket) if {
	sprintf("%s.%s", [bucket.type, bucket.name]) in config(rc).expressions.bucket.references
}

# ---------------------------------------------------------------------------
# TAG-001: all taggable resources have the required tags
# ---------------------------------------------------------------------------

deny contains msg if {
	some rc in taggable_resources
	missing := required_tags - object.keys(tags(rc))
	count(missing) > 0
	msg := sprintf("TAG-001: %s is missing required tags: %v", [rc.address, sort(missing)])
}

deny contains msg if {
	some rc in taggable_resources
	env := tags(rc).Environment
	not env in allowed_environments
	msg := sprintf("TAG-001: %s has Environment=%q; must be one of %v", [rc.address, env, sort(allowed_environments)])
}

# ---------------------------------------------------------------------------
# TAG-002: ApplicationID format is APP-NNNNN and is registered in appid-service
# ---------------------------------------------------------------------------

deny contains msg if {
	some rc in taggable_resources
	app_id := tags(rc).ApplicationID
	not regex.match(`^APP-[0-9]{5}$`, app_id)
	msg := sprintf("TAG-002: %s has ApplicationID=%q; expected format APP-NNNNN (e.g. APP-00001)", [rc.address, app_id])
}

# Only well-formed IDs are looked up; identical requests are cached per query.
validate_app_id(app_id) := http.send({
	"method": "GET",
	"url": sprintf("%s/v1/applications/%s/validate", [appid_service_url, app_id]),
	"headers": auth_headers,
	"raise_error": false,
})

auth_headers := {"Authorization": sprintf("Bearer %s", [appid_service_token])} if {
	appid_service_token != ""
} else := {}

# Fail closed: anything other than an explicit {"valid": true} is unregistered.
registered(app_id) if validate_app_id(app_id).body.valid == true

deny contains msg if {
	some rc in taggable_resources
	app_id := tags(rc).ApplicationID
	regex.match(`^APP-[0-9]{5}$`, app_id)
	validate_app_id(app_id).status_code != 200
	msg := sprintf("TAG-002: %s ApplicationID=%q could not be verified; appid-service at %s returned HTTP %d (0 = unreachable)", [rc.address, app_id, appid_service_url, validate_app_id(app_id).status_code])
}

deny contains msg if {
	some rc in taggable_resources
	app_id := tags(rc).ApplicationID
	regex.match(`^APP-[0-9]{5}$`, app_id)
	validate_app_id(app_id).status_code == 200
	not registered(app_id)
	msg := sprintf("TAG-002: %s has ApplicationID=%q, which is not registered in appid-service", [rc.address, app_id])
}

# ---------------------------------------------------------------------------
# S3-001: each bucket has a public access block with all 4 flags enabled
# ---------------------------------------------------------------------------

has_full_public_access_block(bucket) if {
	some pab in planned_resources
	pab.type == "aws_s3_bucket_public_access_block"
	references_bucket(pab, bucket)
	every flag in public_access_flags {
		pab.change.after[flag] == true
	}
}

deny contains msg if {
	some bucket in buckets
	not has_full_public_access_block(bucket)
	msg := sprintf("S3-001: %s needs an aws_s3_bucket_public_access_block with all of %v set to true", [bucket.address, sort(public_access_flags)])
}

# ---------------------------------------------------------------------------
# S3-002: each bucket defaults to SSE-KMS
# ---------------------------------------------------------------------------

has_sse_kms(bucket) if {
	some sse in planned_resources
	sse.type == "aws_s3_bucket_server_side_encryption_configuration"
	references_bucket(sse, bucket)
	some rule in sse.change.after.rule
	some enc in rule.apply_server_side_encryption_by_default
	enc.sse_algorithm == "aws:kms"
}

deny contains msg if {
	some bucket in buckets
	not has_sse_kms(bucket)
	msg := sprintf("S3-002: %s needs an aws_s3_bucket_server_side_encryption_configuration with sse_algorithm = \"aws:kms\"", [bucket.address])
}

# ---------------------------------------------------------------------------
# CHG-001: no deleting or replacing a prod bucket
# ---------------------------------------------------------------------------

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket"
	"delete" in rc.change.actions
	rc.change.before.tags_all.Environment == "prod"
	msg := sprintf("CHG-001: %s is tagged Environment=prod and must not be deleted or replaced (actions: %v)", [rc.address, rc.change.actions])
}

# ---------------------------------------------------------------------------
# Decision document for scripts/evaluate.sh and the deploy gate
# ---------------------------------------------------------------------------

# Every deny message has the form "<RULE>: <resource address> <details>".
violations := [v |
	some msg in deny
	parts := regex.find_all_string_submatch_n(`^([A-Z0-9]+-[0-9]+): (\S+) (.*)$`, msg, 1)[0]
	v := {"rule": parts[1], "resource": parts[2], "message": parts[3]}
]

decision := {
	"allow": count(deny) == 0,
	"violations": count(deny),
	"deny": violations,
}

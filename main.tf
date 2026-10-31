# Compliant
terraform {
  required_version = ">= 1.10.0"

  # Partial config: bucket, key and region are passed with -backend-config.
  backend "s3" {
    use_lockfile = true
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.region

  # Mandatory tags are applied once here; the policy merges these with
  # resource-level tags when tags_all is not yet known at plan time.
  default_tags {
    tags = {
      ApplicationID = var.application_id
      Environment   = var.environment
      Owner         = var.owner
      CostCenter    = var.cost_center
      ManagedBy     = "terraform"
    }
  }
}

# data "aws_vpc" "default" {
#   default = true
# }

resource "aws_kms_key" "this" {
  description             = "${var.name}-${var.environment} data key."
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

resource "aws_s3_bucket" "this" {
  bucket_prefix = "${var.name}-${var.environment}-"
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.this.arn
    }
    bucket_key_enabled = true
  }
}



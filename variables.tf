variable "region" {
  description = "AWS region to deploy resources into"
  type        = string
  default     = "us-east-1"
}

variable "name" {
  description = "Prefix for resource names."
  type        = string
}

variable "application_id" {
  description = "Application Registry ID (APP-NNNNN), verified live by the policy."
  type        = string
}

variable "environment" {
  description = "Deployment environment (e.g. dev, staging, prod)"
  type        = string

  validation {
    condition     = contains(["dev", "stg", "prod"], var.environment)
    error_message = "environment must be one of: dev, stg, prod."
  }
}

variable "owner" {
  description = "Owner responsible for these resources"
  type        = string
}

variable "cost_center" {
  description = "Cost center to associate with these resources for billing"
  type        = string
}

variable "aws_account_id" {
  type        = string
  description = "12-digit AWS test-account ID. Never use a production account."
  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id))
    error_message = "aws_account_id must have 12 digits."
  }
}

variable "aws_region" {
  type        = string
  description = "AWS Region for the one-region student lab."
}

variable "lab_tag" {
  type        = string
  description = "Common CyberHealLab tag for all test resources."
  default     = "cyberheal-student-lab"
  validation {
    condition     = can(regex("^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,63}$", var.lab_tag))
    error_message = "Use a simple lab tag up to 64 characters."
  }
}

variable "test_instance_type" {
  type        = string
  description = "Check capacity and price before applying; small types may be tight for Wazuh agent."
  default     = "t3.small"
}

variable "verifier_instance_type" {
  type    = string
  default = "t3.micro"
}

variable "data_volume_size_gib" {
  type    = number
  default = 8
  validation {
    condition     = var.data_volume_size_gib >= 1 && var.data_volume_size_gib <= 50
    error_message = "Student test volume must be 1-50 GiB."
  }
}

variable "enable_verifier" {
  type        = bool
  default     = false
  description = "Explicit opt-in creates a second EC2 instance for isolated verification."
}

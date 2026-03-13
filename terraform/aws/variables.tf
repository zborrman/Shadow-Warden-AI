# ──────────────────────────────────────────────────────────────────────────────
# Shadow Warden AI — AWS Terraform variables
# ──────────────────────────────────────────────────────────────────────────────

variable "aws_region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment tag (prod | staging | dev)."
  type        = string
  default     = "prod"
  validation {
    condition     = contains(["prod", "staging", "dev"], var.environment)
    error_message = "environment must be prod, staging, or dev."
  }
}

variable "name_prefix" {
  description = "Prefix for all AWS resource names."
  type        = string
  default     = "shadow-warden"
}

# ── Networking ────────────────────────────────────────────────────────────────

variable "vpc_cidr" {
  description = "CIDR block for the dedicated VPC."
  type        = string
  default     = "10.10.0.0/16"
}

variable "availability_zones" {
  description = "List of AZs to spread subnets across (minimum 2)."
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "private_subnet_cidrs" {
  description = "CIDRs for private subnets (ECS tasks run here)."
  type        = list(string)
  default     = ["10.10.1.0/24", "10.10.2.0/24"]
}

variable "public_subnet_cidrs" {
  description = "CIDRs for public subnets (ALB listeners)."
  type        = list(string)
  default     = ["10.10.101.0/24", "10.10.102.0/24"]
}

# ── Container images ──────────────────────────────────────────────────────────

variable "warden_image_tag" {
  description = "Docker image tag to deploy for the warden service."
  type        = string
  default     = "1.3.0"
}

variable "feed_image_tag" {
  description = "Docker image tag to deploy for the feed server."
  type        = string
  default     = "1.3.0"
}

# ── ECS ───────────────────────────────────────────────────────────────────────

variable "warden_cpu" {
  description = "CPU units for the warden Fargate task (1024 = 1 vCPU)."
  type        = number
  default     = 1024
}

variable "warden_memory" {
  description = "Memory (MiB) for the warden Fargate task."
  type        = number
  default     = 2048
}

variable "warden_desired_count" {
  description = "Desired ECS task count for the warden service."
  type        = number
  default     = 2
}

variable "warden_max_count" {
  description = "Maximum task count for warden auto-scaling."
  type        = number
  default     = 10
}

variable "feed_cpu" {
  description = "CPU units for the feed-server Fargate task."
  type        = number
  default     = 512
}

variable "feed_memory" {
  description = "Memory (MiB) for the feed-server Fargate task."
  type        = number
  default     = 1024
}

# ── TLS / ACM ─────────────────────────────────────────────────────────────────

variable "acm_certificate_arn" {
  description = "ARN of the ACM certificate for HTTPS on the ALB. Leave empty to use HTTP only."
  type        = string
  default     = ""
}

variable "domain_name" {
  description = "Custom domain name for the ALB (optional, for Route 53 record)."
  type        = string
  default     = ""
}

variable "route53_zone_id" {
  description = "Route 53 hosted zone ID for the domain_name record (optional)."
  type        = string
  default     = ""
}

# ── Secrets (inject via AWS Secrets Manager or --var flag) ───────────────────

variable "anthropic_api_key_secret_arn" {
  description = "ARN of the Secrets Manager secret containing ANTHROPIC_API_KEY."
  type        = string
  default     = ""
  sensitive   = true
}

variable "warden_api_key_secret_arn" {
  description = "ARN of the Secrets Manager secret containing WARDEN_API_KEY."
  type        = string
  default     = ""
  sensitive   = true
}

# ── Observability ─────────────────────────────────────────────────────────────

variable "log_retention_days" {
  description = "CloudWatch Logs retention period in days."
  type        = number
  default     = 30
}

# ──────────────────────────────────────────────────────────────────────────────
# Shadow Warden AI — AWS Terraform outputs
# ──────────────────────────────────────────────────────────────────────────────

output "alb_dns_name" {
  description = "Public DNS name of the Application Load Balancer."
  value       = aws_lb.main.dns_name
}

output "warden_url" {
  description = "Shadow Warden gateway endpoint (HTTP or HTTPS)."
  value = var.acm_certificate_arn != "" ? (
    var.domain_name != "" ? "https://${var.domain_name}" : "https://${aws_lb.main.dns_name}"
  ) : "http://${aws_lb.main.dns_name}"
}

output "feed_url" {
  description = "Threat Intelligence Feed server endpoint."
  value = var.acm_certificate_arn != "" ? (
    var.domain_name != "" ? "https://${var.domain_name}/feed.json" : "https://${aws_lb.main.dns_name}/feed.json"
  ) : "http://${aws_lb.main.dns_name}/feed.json"
}

output "ecr_warden_uri" {
  description = "ECR repository URI for the warden gateway image."
  value       = aws_ecr_repository.warden.repository_url
}

output "ecr_feed_uri" {
  description = "ECR repository URI for the feed server image."
  value       = aws_ecr_repository.feed.repository_url
}

output "ecs_cluster_name" {
  description = "ECS cluster name."
  value       = aws_ecs_cluster.main.name
}

output "vpc_id" {
  description = "VPC ID."
  value       = aws_vpc.main.id
}

output "private_subnet_ids" {
  description = "Private subnet IDs (ECS tasks)."
  value       = aws_subnet.private[*].id
}

output "push_commands" {
  description = "Docker push commands for warden and feed images."
  value = <<-EOT
    # Authenticate to ECR
    aws ecr get-login-password --region ${var.aws_region} \
      | docker login --username AWS --password-stdin ${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com

    # Build & push warden gateway
    docker build -t ${aws_ecr_repository.warden.repository_url}:${var.warden_image_tag} \
      -f warden/Dockerfile .
    docker push ${aws_ecr_repository.warden.repository_url}:${var.warden_image_tag}

    # Push feed server (same image, different command)
    docker tag ${aws_ecr_repository.warden.repository_url}:${var.warden_image_tag} \
               ${aws_ecr_repository.feed.repository_url}:${var.feed_image_tag}
    docker push ${aws_ecr_repository.feed.repository_url}:${var.feed_image_tag}
  EOT
}

# ──────────────────────────────────────────────────────────────────────────────
# Shadow Warden AI — AWS ECS Fargate deployment
#
# Topology
# ─────────
#   VPC (10.10.0.0/16)
#     Public subnets  → ALB (HTTPS 443 / HTTP 80 redirect)
#     Private subnets → ECS Fargate tasks (warden:8001, feed:8003)
#       NAT Gateway   → tasks can pull ECR images & call external APIs
#
# AWS Marketplace readiness
# ─────────────────────────
#   • ECR repositories for all images (AMI-less container listing)
#   • IAM roles with least-privilege policies
#   • Secrets Manager integration (no env-var secrets in task definitions)
#   • CloudWatch Logs with configurable retention
#   • Application Auto Scaling on CPU & memory
#
# Usage
# ─────
#   terraform init
#   terraform plan -var="environment=prod"
#   terraform apply -var="environment=prod"
# ──────────────────────────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Recommended: store state in S3 + DynamoDB lock
  # backend "s3" {
  #   bucket         = "your-terraform-state-bucket"
  #   key            = "shadow-warden/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "terraform-locks"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "shadow-warden"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# ── Data sources ──────────────────────────────────────────────────────────────

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ── VPC ───────────────────────────────────────────────────────────────────────

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "${var.name_prefix}-vpc" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.name_prefix}-igw" }
}

resource "aws_subnet" "public" {
  count                   = length(var.public_subnet_cidrs)
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = true

  tags = { Name = "${var.name_prefix}-public-${count.index + 1}" }
}

resource "aws_subnet" "private" {
  count             = length(var.private_subnet_cidrs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = { Name = "${var.name_prefix}-private-${count.index + 1}" }
}

resource "aws_eip" "nat" {
  count  = 1
  domain = "vpc"
  tags   = { Name = "${var.name_prefix}-nat-eip" }
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public[0].id
  tags          = { Name = "${var.name_prefix}-nat" }
  depends_on    = [aws_internet_gateway.main]
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
  tags = { Name = "${var.name_prefix}-rt-public" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }
  tags = { Name = "${var.name_prefix}-rt-private" }
}

resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count          = length(aws_subnet.private)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# ── Security Groups ───────────────────────────────────────────────────────────

resource "aws_security_group" "alb" {
  name        = "${var.name_prefix}-alb-sg"
  description = "ALB — allows inbound HTTP/HTTPS from the internet"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  dynamic "ingress" {
    for_each = var.acm_certificate_arn != "" ? [1] : []
    content {
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name_prefix}-alb-sg" }
}

resource "aws_security_group" "warden" {
  name        = "${var.name_prefix}-warden-sg"
  description = "Warden ECS tasks — inbound from ALB only"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 8001
    to_port         = 8001
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name_prefix}-warden-sg" }
}

resource "aws_security_group" "feed" {
  name        = "${var.name_prefix}-feed-sg"
  description = "Feed server ECS tasks — inbound from ALB only"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 8003
    to_port         = 8003
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name_prefix}-feed-sg" }
}

# ── CloudWatch Logs ───────────────────────────────────────────────────────────

resource "aws_cloudwatch_log_group" "warden" {
  name              = "/ecs/${var.name_prefix}/warden"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "feed" {
  name              = "/ecs/${var.name_prefix}/feed"
  retention_in_days = var.log_retention_days
}

# ── IAM ───────────────────────────────────────────────────────────────────────

resource "aws_iam_role" "ecs_task_execution" {
  name = "${var.name_prefix}-ecs-task-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution_managed" {
  role       = aws_iam_role.ecs_task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "ecs_secrets" {
  count = (var.anthropic_api_key_secret_arn != "" || var.warden_api_key_secret_arn != "") ? 1 : 0
  name  = "${var.name_prefix}-ecs-secrets"
  role  = aws_iam_role.ecs_task_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["secretsmanager:GetSecretValue"]
      Resource = compact([
        var.anthropic_api_key_secret_arn,
        var.warden_api_key_secret_arn,
      ])
    }]
  })
}

resource "aws_iam_role" "ecs_task" {
  name = "${var.name_prefix}-ecs-task"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "ecs_task_logs" {
  name = "${var.name_prefix}-ecs-task-logs"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = ["${aws_cloudwatch_log_group.warden.arn}:*", "${aws_cloudwatch_log_group.feed.arn}:*"]
    }]
  })
}

# ── ECS Cluster ───────────────────────────────────────────────────────────────

resource "aws_ecs_cluster" "main" {
  name = "${var.name_prefix}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_ecs_cluster_capacity_providers" "main" {
  cluster_name       = aws_ecs_cluster.main.name
  capacity_providers = ["FARGATE", "FARGATE_SPOT"]

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
    base              = 1
  }
}

# ── ECR Repositories ──────────────────────────────────────────────────────────

resource "aws_ecr_repository" "warden" {
  name                 = "${var.name_prefix}/gateway"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }
}

resource "aws_ecr_repository" "feed" {
  name                 = "${var.name_prefix}/feed-server"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }
}

resource "aws_ecr_lifecycle_policy" "warden" {
  repository = aws_ecr_repository.warden.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep last 10 tagged images"
      selection = {
        tagStatus   = "tagged"
        tagPrefixList = ["v"]
        countType   = "imageCountMoreThan"
        countNumber = 10
      }
      action = { type = "expire" }
    }]
  })
}

# ── ALB ───────────────────────────────────────────────────────────────────────

resource "aws_lb" "main" {
  name               = "${var.name_prefix}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id

  enable_deletion_protection = var.environment == "prod"

  access_logs {
    bucket  = ""   # Set to an S3 bucket name to enable ALB access logs
    enabled = false
  }
}

resource "aws_lb_target_group" "warden" {
  name        = "${var.name_prefix}-warden-tg"
  port        = 8001
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    path                = "/health"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 30
    timeout             = 5
    matcher             = "200"
  }

  deregistration_delay = 30
}

resource "aws_lb_target_group" "feed" {
  name        = "${var.name_prefix}-feed-tg"
  port        = 8003
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    path                = "/health"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 30
    timeout             = 5
    matcher             = "200"
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  # Redirect to HTTPS if certificate is provided, otherwise forward
  dynamic "default_action" {
    for_each = var.acm_certificate_arn != "" ? [1] : []
    content {
      type = "redirect"
      redirect {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }
  }

  dynamic "default_action" {
    for_each = var.acm_certificate_arn == "" ? [1] : []
    content {
      type             = "forward"
      target_group_arn = aws_lb_target_group.warden.arn
    }
  }
}

resource "aws_lb_listener" "https" {
  count             = var.acm_certificate_arn != "" ? 1 : 0
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.acm_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.warden.arn
  }
}

resource "aws_lb_listener_rule" "feed" {
  listener_arn = var.acm_certificate_arn != "" ? aws_lb_listener.https[0].arn : aws_lb_listener.http.arn
  priority     = 10

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.feed.arn
  }

  condition {
    path_pattern {
      values = ["/feed*", "/rules*", "/admin/*"]
    }
  }
}

# ── ECS Task Definitions ──────────────────────────────────────────────────────

locals {
  warden_image = "${aws_ecr_repository.warden.repository_url}:${var.warden_image_tag}"
  feed_image   = "${aws_ecr_repository.feed.repository_url}:${var.feed_image_tag}"

  warden_secrets = concat(
    var.anthropic_api_key_secret_arn != "" ? [{
      name      = "ANTHROPIC_API_KEY"
      valueFrom = var.anthropic_api_key_secret_arn
    }] : [],
    var.warden_api_key_secret_arn != "" ? [{
      name      = "WARDEN_API_KEY"
      valueFrom = var.warden_api_key_secret_arn
    }] : [],
  )
}

resource "aws_ecs_task_definition" "warden" {
  family                   = "${var.name_prefix}-warden"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.warden_cpu
  memory                   = var.warden_memory
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([{
    name      = "warden"
    image     = local.warden_image
    essential = true

    portMappings = [{
      containerPort = 8001
      protocol      = "tcp"
    }]

    environment = [
      { name = "LOGS_PATH",             value = "/tmp/warden_logs.json" },
      { name = "DYNAMIC_RULES_PATH",    value = "/tmp/warden_rules.json" },
      { name = "REDIS_URL",             value = "memory://" },
      { name = "SEMANTIC_THRESHOLD",    value = "0.72" },
      { name = "STRICT_MODE",           value = "false" },
      { name = "MODEL_CACHE_DIR",       value = "/tmp/models" },
      { name = "LOG_LEVEL",             value = "info" },
    ]

    secrets = local.warden_secrets

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.warden.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "warden"
      }
    }

    healthCheck = {
      command     = ["CMD-SHELL", "python -c \"import urllib.request; urllib.request.urlopen('http://localhost:8001/health')\" || exit 1"]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 60
    }

    readonlyRootFilesystem = false
    linuxParameters = {
      sharedMemorySize = 512   # MiB — for Playwright Chromium
    }
  }])
}

resource "aws_ecs_task_definition" "feed" {
  family                   = "${var.name_prefix}-feed"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.feed_cpu
  memory                   = var.feed_memory
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([{
    name      = "feed"
    image     = local.feed_image
    essential = true

    command = ["uvicorn", "warden.feed_server.main:app",
               "--host", "0.0.0.0", "--port", "8003", "--workers", "2"]

    portMappings = [{
      containerPort = 8003
      protocol      = "tcp"
    }]

    environment = [
      { name = "FEED_DB_PATH",        value = "/tmp/feed_server.db" },
      { name = "FEED_PUBLIC",         value = "false" },
      { name = "FEED_MIN_VET_SOURCES", value = "2" },
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.feed.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "feed"
      }
    }

    healthCheck = {
      command     = ["CMD-SHELL", "python -c \"import urllib.request; urllib.request.urlopen('http://localhost:8003/health')\" || exit 1"]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 30
    }
  }])
}

# ── ECS Services ──────────────────────────────────────────────────────────────

resource "aws_ecs_service" "warden" {
  name            = "${var.name_prefix}-warden"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.warden.arn
  desired_count   = var.warden_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.warden.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.warden.arn
    container_name   = "warden"
    container_port   = 8001
  }

  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  lifecycle {
    ignore_changes = [desired_count]
  }

  depends_on = [aws_lb_listener.http]
}

resource "aws_ecs_service" "feed" {
  name            = "${var.name_prefix}-feed"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.feed.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.feed.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.feed.arn
    container_name   = "feed"
    container_port   = 8003
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  depends_on = [aws_lb_listener.http]
}

# ── Application Auto Scaling (warden) ─────────────────────────────────────────

resource "aws_appautoscaling_target" "warden" {
  max_capacity       = var.warden_max_count
  min_capacity       = var.warden_desired_count
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.warden.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "warden_cpu" {
  name               = "${var.name_prefix}-warden-scale-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.warden.resource_id
  scalable_dimension = aws_appautoscaling_target.warden.scalable_dimension
  service_namespace  = aws_appautoscaling_target.warden.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value       = 70
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}

resource "aws_appautoscaling_policy" "warden_memory" {
  name               = "${var.name_prefix}-warden-scale-mem"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.warden.resource_id
  scalable_dimension = aws_appautoscaling_target.warden.scalable_dimension
  service_namespace  = aws_appautoscaling_target.warden.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageMemoryUtilization"
    }
    target_value       = 80
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}

# ── Route 53 (optional) ───────────────────────────────────────────────────────

resource "aws_route53_record" "warden" {
  count   = var.domain_name != "" && var.route53_zone_id != "" ? 1 : 0
  zone_id = var.route53_zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = aws_lb.main.dns_name
    zone_id                = aws_lb.main.zone_id
    evaluate_target_health = true
  }
}

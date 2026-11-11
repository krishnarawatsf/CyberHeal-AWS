# CyberHeal AWS student lab: one EC2 test workload and a separately attached
# EBS data volume. Optionally add a *temporary* verifier instance.
# Prerequisite: an existing default VPC and default public subnet.
# Do not apply to a shared or production AWS account.

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_vpc" "default" {
  default = true
}
data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}
data "aws_subnet" "selected" {
  id = sort(data.aws_subnets.default.ids)[0]
}
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

locals {
  common_tags = {
    CyberHealLab = var.lab_tag
    Project      = "CyberHeal-AWS"
    Environment  = "isolated-student-demo"
    ManagedBy    = "OpenTofu-MemberC"
  }
}

resource "aws_security_group" "no_inbound" {
  name_prefix = "${var.lab_tag}-ssm-"
  description = "CyberHeal lab SSM-only: zero inbound rules"
  vpc_id      = data.aws_vpc.default.id
  # SSM uses HTTPS; no inbound or unrestricted egress rules.
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = merge(local.common_tags, { Name = "cyberheal-ssm-no-inbound" })
}

# B's quarantine target: zero ingress and zero egress rules. Applying it
# to the test EC2 instance will also disconnect Systems Manager access.
# Reattach the original group via AWS Console to restore management access.
resource "aws_security_group" "quarantine" {
  name_prefix = "${var.lab_tag}-quarantine-"
  description = "CyberHeal lab quarantine: no ingress or egress"
  vpc_id      = data.aws_vpc.default.id
  ingress     = []
  egress      = []
  tags        = merge(local.common_tags, { Name = "cyberheal-quarantine" })
}

resource "aws_iam_role" "ssm_instance" {
  name_prefix = "cyberheal-ssm-"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.ssm_instance.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ssm" {
  name_prefix = "cyberheal-ssm-"
  role        = aws_iam_role.ssm_instance.name
}

resource "aws_instance" "test_workload" {
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = var.test_instance_type
  subnet_id                   = data.aws_subnet.selected.id
  vpc_security_group_ids      = [aws_security_group.no_inbound.id]
  associate_public_ip_address = true # Charged public IPv4; needed for SSM via internet in this minimal design.
  iam_instance_profile        = aws_iam_instance_profile.ssm.name
  metadata_options {
    http_tokens = "required"
  }
  root_block_device {
    encrypted             = true
    volume_size           = 12
    volume_type           = "gp3"
    delete_on_termination = true
  }
  lifecycle {
    precondition {
      condition     = data.aws_caller_identity.current.account_id == var.aws_account_id
      error_message = "AWS account does not match approved lab account."
    }
  }
  tags = merge(local.common_tags, { Name = "cyberheal-test-workload" })
}

resource "aws_ebs_volume" "sample_data" {
  availability_zone = data.aws_subnet.selected.availability_zone
  size              = var.data_volume_size_gib
  type              = "gp3"
  encrypted         = true
  tags              = merge(local.common_tags, { Name = "cyberheal-sample-data" })
  lifecycle {
    prevent_destroy = true # Remove only after operator reviews backups and costs.
  }
}

resource "aws_volume_attachment" "sample_data" {
  device_name  = "/dev/sdf"
  volume_id    = aws_ebs_volume.sample_data.id
  instance_id  = aws_instance.test_workload.id
  force_detach = false
}

resource "aws_instance" "verifier" {
  count                       = var.enable_verifier ? 1 : 0
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = var.verifier_instance_type
  subnet_id                   = data.aws_subnet.selected.id
  vpc_security_group_ids      = [aws_security_group.no_inbound.id]
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.ssm.name
  metadata_options {
    http_tokens = "required"
  }
  root_block_device {
    encrypted             = true
    volume_size           = 12
    volume_type           = "gp3"
    delete_on_termination = true
  }
  tags = merge(local.common_tags, { Name = "cyberheal-isolated-verifier", Role = "CyberHealVerifier" })
}

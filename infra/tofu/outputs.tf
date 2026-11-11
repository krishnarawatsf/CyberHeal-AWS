output "aws_account_id" {
  value = data.aws_caller_identity.current.account_id
}
output "region" {
  value = var.aws_region
}
output "availability_zone" {
  value = data.aws_subnet.selected.availability_zone
}
output "test_instance_id" {
  value = aws_instance.test_workload.id
}
output "sample_data_volume_id" {
  value = aws_ebs_volume.sample_data.id
}
output "verifier_instance_id" {
  value = try(aws_instance.verifier[0].id, null)
}
output "security_group_id" {
  value = aws_security_group.no_inbound.id
}
output "lab_tag" {
  value = var.lab_tag
}

output "quarantine_security_group_id" {
  value = aws_security_group.quarantine.id
}

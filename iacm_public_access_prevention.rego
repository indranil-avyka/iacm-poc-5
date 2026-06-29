package iacm.public_access_prevention

sensitive_ports := {22, 3389}

deny[msg] {
  r := input.plan.resource_changes[_]
  is_create_or_update(r)
  r.type == "aws_security_group"

  ingress := object.get(r.change.after, "ingress", [])[_]
  cidr := object.get(ingress, "cidr_blocks", [])[_]
  cidr == "0.0.0.0/0"

  port := sensitive_ports[_]
  port_in_range(ingress, port)

  msg := sprintf(
    "Public access policy violation: AWS Security Group '%s' allows public ingress from 0.0.0.0/0 on sensitive port %v.",
    [r.address, port],
  )
}

deny[msg] {
  r := input.plan.resource_changes[_]
  is_create_or_update(r)
  r.type == "aws_security_group"

  ingress := object.get(r.change.after, "ingress", [])[_]
  cidr := object.get(ingress, "ipv6_cidr_blocks", [])[_]
  cidr == "::/0"

  port := sensitive_ports[_]
  port_in_range(ingress, port)

  msg := sprintf(
    "Public access policy violation: AWS Security Group '%s' allows public IPv6 ingress from ::/0 on sensitive port %v.",
    [r.address, port],
  )
}

deny[msg] {
  r := input.plan.resource_changes[_]
  is_create_or_update(r)
  r.type == "aws_security_group_rule"
  object.get(r.change.after, "type", "") == "ingress"

  cidr := object.get(r.change.after, "cidr_blocks", [])[_]
  cidr == "0.0.0.0/0"

  port := sensitive_ports[_]
  port_in_range(r.change.after, port)

  msg := sprintf(
    "Public access policy violation: AWS Security Group Rule '%s' allows public ingress from 0.0.0.0/0 on sensitive port %v.",
    [r.address, port],
  )
}

deny[msg] {
  r := input.plan.resource_changes[_]
  is_create_or_update(r)
  r.type == "aws_security_group_rule"
  object.get(r.change.after, "type", "") == "ingress"

  cidr := object.get(r.change.after, "ipv6_cidr_blocks", [])[_]
  cidr == "::/0"

  port := sensitive_ports[_]
  port_in_range(r.change.after, port)

  msg := sprintf(
    "Public access policy violation: AWS Security Group Rule '%s' allows public IPv6 ingress from ::/0 on sensitive port %v.",
    [r.address, port],
  )
}

deny[msg] {
  r := input.plan.resource_changes[_]
  is_create_or_update(r)
  r.type == "aws_s3_bucket"

  not s3_bucket_has_public_access_block(r)

  msg := sprintf(
    "Public access policy violation: AWS S3 bucket '%s' must have an aws_s3_bucket_public_access_block with all block/restrict settings enabled.",
    [r.address],
  )
}

deny[msg] {
  r := input.plan.resource_changes[_]
  is_create_or_update(r)
  r.type == "aws_s3_bucket_public_access_block"

  not s3_public_access_block_fully_enabled(r)

  msg := sprintf(
    "Public access policy violation: AWS S3 public access block '%s' must set block_public_acls, block_public_policy, ignore_public_acls, and restrict_public_buckets to true.",
    [r.address],
  )
}

deny[msg] {
  r := input.plan.resource_changes[_]
  is_create_or_update(r)
  r.type == "azurerm_network_security_rule"
  lower(object.get(r.change.after, "direction", "")) == "inbound"

  source := object.get(r.change.after, "source_address_prefix", "")
  public_source(source)

  port := sensitive_ports[_]
  azure_port_matches(r, port)

  msg := sprintf(
    "Public access policy violation: Azure Network Security Rule '%s' allows public inbound access on sensitive port %v.",
    [r.address, port],
  )
}

port_in_range(rule, port) {
  from_port := object.get(rule, "from_port", -1)
  to_port := object.get(rule, "to_port", -1)
  from_port <= port
  to_port >= port
}

s3_bucket_has_public_access_block(r) {
  bucket_name := object.get(r.change.after, "bucket", "")
  bucket_name != ""

  pab := input.plan.resource_changes[_]
  is_create_or_update(pab)
  pab.type == "aws_s3_bucket_public_access_block"
  object.get(pab.change.after, "bucket", "") == bucket_name
  s3_public_access_block_fully_enabled(pab)
}

s3_public_access_block_fully_enabled(r) {
  object.get(r.change.after, "block_public_acls", false) == true
  object.get(r.change.after, "block_public_policy", false) == true
  object.get(r.change.after, "ignore_public_acls", false) == true
  object.get(r.change.after, "restrict_public_buckets", false) == true
}

public_source(source) {
  source == "*"
}

public_source(source) {
  source == "0.0.0.0/0"
}

public_source(source) {
  lower(source) == "internet"
}

azure_port_matches(r, port) {
  p := object.get(r.change.after, "destination_port_range", "")
  p == sprintf("%v", [port])
}

azure_port_matches(r, port) {
  ranges := object.get(r.change.after, "destination_port_ranges", [])
  ranges[_] == sprintf("%v", [port])
}

is_create_or_update(r) {
  action := r.change.actions[_]
  action == "create"
}

is_create_or_update(r) {
  action := r.change.actions[_]
  action == "update"
}
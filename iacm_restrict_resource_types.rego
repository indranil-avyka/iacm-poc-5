package iacm.restrict_resource_types

# Configurable allowlist of approved Terraform resource types.
allowed_resource_types := {
  "aws_instance",
  "aws_s3_bucket",
  "aws_s3_bucket_public_access_block",
  "aws_s3_bucket_server_side_encryption_configuration",
  "aws_db_instance",
  "aws_rds_cluster",
  "aws_ebs_volume",
  "aws_efs_file_system",
  "aws_security_group",
  "aws_security_group_rule",
  "azurerm_resource_group",
  "azurerm_storage_account",
  "azurerm_linux_virtual_machine",
  "azurerm_windows_virtual_machine",
  "azurerm_managed_disk",
  "azurerm_network_security_group",
  "azurerm_network_security_rule",
  "google_compute_instance",
  "google_storage_bucket",
  "google_sql_database_instance",
}

# Configurable allowlist of approved sizes/SKUs per resource type.
allowed_sizes_by_type := {
  "aws_instance": {
    "t3.micro",
    "t3.small",
    "t3.medium",
    "m6i.large",
  },
  "aws_db_instance": {
    "db.t3.micro",
    "db.t3.small",
    "db.t3.medium",
  },
  "azurerm_linux_virtual_machine": {
    "Standard_B1s",
    "Standard_B2s",
    "Standard_D2s_v5",
  },
  "azurerm_windows_virtual_machine": {
    "Standard_B1s",
    "Standard_B2s",
    "Standard_D2s_v5",
  },
  "google_compute_instance": {
    "e2-micro",
    "e2-small",
    "e2-medium",
  },
  "google_sql_database_instance": {
    "db-f1-micro",
    "db-g1-small",
  },
}

deny[msg] {
  r := input.plan.resource_changes[_]
  is_create_or_update(r)

  not allowed_resource_type(r.type)

  msg := sprintf(
    "Restrict resource types policy violation: resource '%s' uses type '%s', which is not approved. Allowed resource types are: %v.",
    [r.address, r.type, allowed_resource_types],
  )
}

deny[msg] {
  r := input.plan.resource_changes[_]
  is_create_or_update(r)

  allowed_resource_type(r.type)
  size := resource_size(r)

  approved_sizes := object.get(allowed_sizes_by_type, r.type, {})
  count(approved_sizes) > 0

  not approved_size(r.type, size)

  msg := sprintf(
    "Restrict resource types policy violation: resource '%s' of type '%s' uses size/SKU '%s', which is not approved. Approved values for this type are: %v.",
    [r.address, r.type, size, approved_sizes],
  )
}

allowed_resource_type(resource_type) {
  allowed_resource_types[resource_type]
}

approved_size(resource_type, size) {
  allowed_sizes_by_type[resource_type][size]
}

resource_size(r) := size {
  size := object.get(r.change.after, "instance_type", "")
  size != ""
}

resource_size(r) := size {
  size := object.get(r.change.after, "instance_class", "")
  size != ""
}

resource_size(r) := size {
  size := object.get(r.change.after, "vm_size", "")
  size != ""
}

resource_size(r) := size {
  size := object.get(r.change.after, "machine_type", "")
  size != ""
}

resource_size(r) := size {
  settings := object.get(r.change.after, "settings", [])
  count(settings) > 0
  size := object.get(settings[0], "tier", "")
  size != ""
}

is_create_or_update(r) {
  action := r.change.actions[_]
  action == "create"
}

is_create_or_update(r) {
  action := r.change.actions[_]
  action == "update"
}
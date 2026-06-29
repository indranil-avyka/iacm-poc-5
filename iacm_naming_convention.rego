package iacm.naming_convention

# Expected format:
# {env}-{app}-{resource-type}-{number}
#
# Examples:
# dev-payments-s3-001
# prod-billing-rds-002
# stg-platform-vm-003

expected_format := "{env}-{app}-{resource-type}-{number}"
name_regex := "^(dev|qa|test|stg|stage|prod)-[a-z0-9]+-[a-z0-9-]+-[0-9]{3}$"

# Configure resource types that must follow the convention.
enforced_resource_types := {
  "aws_instance",
  "aws_s3_bucket",
  "aws_db_instance",
  "aws_rds_cluster",
  "aws_ebs_volume",
  "aws_lb",
  "azurerm_storage_account",
  "azurerm_resource_group",
  "azurerm_linux_virtual_machine",
  "azurerm_windows_virtual_machine",
  "google_compute_instance",
  "google_storage_bucket",
  "google_sql_database_instance",
}

deny[msg] {
  r := input.plan.resource_changes[_]
  is_create_or_update(r)
  r.type == enforced_resource_types[_]

  name := resource_name(r)
  not regex.match(name_regex, name)

  msg := sprintf(
    "Naming convention policy violation: resource '%s' of type '%s' has name '%s'. Expected format: %s. Example: prod-payments-s3-001.",
    [r.address, r.type, name, expected_format],
  )
}

deny[msg] {
  r := input.plan.resource_changes[_]
  is_create_or_update(r)
  r.type == enforced_resource_types[_]

  not has_resource_name(r)

  msg := sprintf(
    "Naming convention policy violation: resource '%s' of type '%s' does not expose a supported name attribute. Expected naming format: %s. Supported attributes checked: name, bucket, identifier, cluster_identifier, storage_account_name.",
    [r.address, r.type, expected_format],
  )
}

has_resource_name(r) {
  resource_name(r)
}

resource_name(r) := name {
  name := object.get(r.change.after, "name", "")
  name != ""
}

resource_name(r) := name {
  name := object.get(r.change.after, "bucket", "")
  name != ""
}

resource_name(r) := name {
  name := object.get(r.change.after, "identifier", "")
  name != ""
}

resource_name(r) := name {
  name := object.get(r.change.after, "cluster_identifier", "")
  name != ""
}

resource_name(r) := name {
  name := object.get(r.change.after, "storage_account_name", "")
  name != ""
}

is_create_or_update(r) {
  action := r.change.actions[_]
  action == "create"
}

is_create_or_update(r) {
  action := r.change.actions[_]
  action == "update"
}
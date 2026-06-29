package iacm.mandatory_tags

required_tags := {
  "environment",
  "owner",
  "cost-center",
  "managed-by",
}

# Configure the resource types in your org that must carry tags/labels.
taggable_resource_types := {
  "aws_instance",
  "aws_s3_bucket",
  "aws_db_instance",
  "aws_rds_cluster",
  "aws_ebs_volume",
  "aws_efs_file_system",
  "aws_vpc",
  "aws_subnet",
  "aws_lb",
  "aws_eks_cluster",
  "azurerm_resource_group",
  "azurerm_storage_account",
  "azurerm_linux_virtual_machine",
  "azurerm_windows_virtual_machine",
  "azurerm_kubernetes_cluster",
  "azurerm_sql_server",
  "azurerm_mssql_server",
  "google_compute_instance",
  "google_storage_bucket",
  "google_sql_database_instance",
  "google_container_cluster",
}

deny[msg] {
  r := input.plan.resource_changes[_]
  is_create_or_update(r)
  r.type == taggable_resource_types[_]

  missing := missing_tags(r)
  count(missing) > 0

  msg := sprintf(
    "Mandatory tags policy violation: resource '%s' of type '%s' is missing required tag(s): %v. Required tags are: %v.",
    [r.address, r.type, missing, required_tags],
  )
}

missing_tags(r) := missing {
  missing := [tag | tag := required_tags[_]; not has_required_tag(r, tag)]
}

has_required_tag(r, tag) {
  c := tag_container(r)
  val := object.get(c, tag, "")
  val != ""
}

tag_container(r) := c {
  c := object.get(r.change.after, "tags", {})
  is_object(c)
}

tag_container(r) := c {
  c := object.get(r.change.after, "tags_all", {})
  is_object(c)
}

tag_container(r) := c {
  c := object.get(r.change.after, "labels", {})
  is_object(c)
}

is_create_or_update(r) {
  action := r.change.actions[_]
  action == "create"
}

is_create_or_update(r) {
  action := r.change.actions[_]
  action == "update"
}
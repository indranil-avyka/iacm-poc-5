package iacm.storage_encryption

deny[msg] {
  r := input.plan.resource_changes[_]
  is_create_or_update(r)
  r.type == "aws_db_instance"

  not bool_attr_true(r, "storage_encrypted")

  msg := sprintf(
    "Encryption at rest policy violation: AWS RDS instance '%s' must have storage_encrypted = true.",
    [r.address],
  )
}

deny[msg] {
  r := input.plan.resource_changes[_]
  is_create_or_update(r)
  r.type == "aws_rds_cluster"

  not bool_attr_true(r, "storage_encrypted")

  msg := sprintf(
    "Encryption at rest policy violation: AWS RDS cluster '%s' must have storage_encrypted = true.",
    [r.address],
  )
}

deny[msg] {
  r := input.plan.resource_changes[_]
  is_create_or_update(r)
  r.type == "aws_ebs_volume"

  not bool_attr_true(r, "encrypted")

  msg := sprintf(
    "Encryption at rest policy violation: AWS EBS volume '%s' must have encrypted = true.",
    [r.address],
  )
}

deny[msg] {
  r := input.plan.resource_changes[_]
  is_create_or_update(r)
  r.type == "aws_efs_file_system"

  not bool_attr_true(r, "encrypted")

  msg := sprintf(
    "Encryption at rest policy violation: AWS EFS file system '%s' must have encrypted = true.",
    [r.address],
  )
}

deny[msg] {
  r := input.plan.resource_changes[_]
  is_create_or_update(r)
  r.type == "aws_s3_bucket"

  not s3_bucket_has_encryption(r)

  msg := sprintf(
    "Encryption at rest policy violation: AWS S3 bucket '%s' must have server-side encryption configured using aws_s3_bucket_server_side_encryption_configuration or an inline encryption block.",
    [r.address],
  )
}

deny[msg] {
  r := input.plan.resource_changes[_]
  is_create_or_update(r)
  r.type == "azurerm_storage_account"

  not bool_attr_true(r, "infrastructure_encryption_enabled")

  msg := sprintf(
    "Encryption at rest policy violation: Azure Storage Account '%s' must explicitly set infrastructure_encryption_enabled = true.",
    [r.address],
  )
}

deny[msg] {
  r := input.plan.resource_changes[_]
  is_create_or_update(r)
  r.type == "azurerm_managed_disk"

  not azure_managed_disk_encrypted(r)

  msg := sprintf(
    "Encryption at rest policy violation: Azure Managed Disk '%s' must use disk_encryption_set_id or encryption_settings.",
    [r.address],
  )
}

deny[msg] {
  r := input.plan.resource_changes[_]
  is_create_or_update(r)
  r.type == "google_storage_bucket"

  not gcs_bucket_encrypted(r)

  msg := sprintf(
    "Encryption at rest policy violation: Google Cloud Storage bucket '%s' must configure encryption.default_kms_key_name.",
    [r.address],
  )
}

deny[msg] {
  r := input.plan.resource_changes[_]
  is_create_or_update(r)
  r.type == "google_sql_database_instance"

  not gcp_sql_encrypted(r)

  msg := sprintf(
    "Encryption at rest policy violation: Google Cloud SQL instance '%s' must configure disk_encryption_configuration.kms_key_name.",
    [r.address],
  )
}

bool_attr_true(r, attr) {
  object.get(r.change.after, attr, false) == true
}

s3_bucket_has_encryption(r) {
  enc := object.get(r.change.after, "server_side_encryption_configuration", null)
  enc != null
}

s3_bucket_has_encryption(r) {
  bucket_name := object.get(r.change.after, "bucket", "")
  bucket_name != ""

  enc_resource := input.plan.resource_changes[_]
  is_create_or_update(enc_resource)
  enc_resource.type == "aws_s3_bucket_server_side_encryption_configuration"
  object.get(enc_resource.change.after, "bucket", "") == bucket_name
}

azure_managed_disk_encrypted(r) {
  object.get(r.change.after, "disk_encryption_set_id", "") != ""
}

azure_managed_disk_encrypted(r) {
  settings := object.get(r.change.after, "encryption_settings", [])
  count(settings) > 0
}

gcs_bucket_encrypted(r) {
  enc := object.get(r.change.after, "encryption", [])
  count(enc) > 0
  object.get(enc[0], "default_kms_key_name", "") != ""
}

gcp_sql_encrypted(r) {
  enc := object.get(r.change.after, "disk_encryption_configuration", [])
  count(enc) > 0
  object.get(enc[0], "kms_key_name", "") != ""
}

is_create_or_update(r) {
  action := r.change.actions[_]
  action == "create"
}

is_create_or_update(r) {
  action := r.change.actions[_]
  action == "update"
}
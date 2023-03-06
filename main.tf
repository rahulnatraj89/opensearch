provider "aws" {
    region = "var.region"
}


locals {
  region = var.region
}

data "aws_caller_identity" "current" {}

data "aws_vpc" "selected" {
  count = var.inside_vpc ? 1 : 0
  id    = var.vpc
}

data "aws_subnet" "selected" {
  for_each = toset(var.subnet_ids)
  id       = each.key
}


/*resource "aws_security_group" "os" {
  count       = var.inside_vpc ? 1 : 0
  name        = "${var.vpc}-elasticsearch"
  description = "Managed by Terraform"
  vpc_id      = data.aws_vpc.selected[0].id

}*/

/*resource "aws_iam_service_linked_role" "os" {
  aws_service_name = var.aws_service_name_for_linked_role
}

resource "time_sleep" "role_dependency" {
  create_duration = "10s"

  triggers = {
    #role_arn       = try(aws_iam_role.cognito_es_role[0].arn, null),
    linked_role_id = try(aws_iam_service_linked_role.os.id, "11111")
  }
}*/

resource "aws_opensearch_domain" "opensearch" {
  domain_name    = var.name
  engine_version = var.engine_version

  advanced_security_options {
    enabled                        = var.advanced_security_options_enabled
    internal_user_database_enabled = var.internal_user_database_enabled
    master_user_options {
      master_user_arn      = "var.master_user_arn"
      #master_user_name     = var.internal_user_database_enabled ? var.master_user_name : ""
      #master_user_password = var.internal_user_database_enabled ? random_password.password.result : ""
    }
  }

  advanced_options = var.advanced_options

  dynamic "vpc_options" {
    for_each = var.inside_vpc ? [1] : []
    content {
      subnet_ids         = var.subnet_ids
      security_group_ids = var.security_group_ids
    }
    
  }


  cluster_config {
    instance_type            = var.instance_type
    dedicated_master_enabled = try(var.cluster_config["dedicated_master_enabled"], true)
    dedicated_master_count   = try(var.cluster_config["dedicated_master_count"], 3)
    dedicated_master_type    = try(var.cluster_config["dedicated_master_type"], "r6g.large.search")
    instance_count           = try(var.cluster_config["instance_count"], 6)
    warm_enabled             = try(var.cluster_config["warm_enabled"], true)
    warm_count               = try(var.cluster_config["warm_enabled"], true) ? try(var.cluster_config["warm_count"], 3) : null
    warm_type                = try(var.cluster_config["warm_type"], true) ? try(var.cluster_config["warm_type"], var.warm_type) : null
    zone_awareness_enabled   = try(var.cluster_config["zone_awareness_enabled"], true)
    dynamic "zone_awareness_config" {
      for_each = try(var.cluster_config["availability_zone_count"], 2) > 2 && try(var.cluster_config["zone_awareness_enabled"], true) ? [2] : []
      content {
        availability_zone_count = try(var.cluster_config["availablity_zone_count"], 2)
      }
    }
  }

  encrypt_at_rest {
    enabled    = try(var.encrypt_at_rest["enabled"], true)
    kms_key_id = try(var.encrypt_at_rest["kms_key_id"], "var.kms_key_id")
  }

  dynamic "log_publishing_options" {
    for_each = try(var.log_publishing_options["audit_logs_enabled"], false) ? [1] : []
    content {
      enabled                  = try(var.log_publishing_options["audit_logs_enabled"], false)
      log_type                 = "AUDIT_LOGS"
      cloudwatch_log_group_arn = try(var.log_publishing_options["audit_logs_cw_log_group_arn"], null)
    }
  }

  dynamic "log_publishing_options" {
    for_each = try(var.log_publishing_options["application_logs_enabled"], false) ? [1] : []
    content {
      enabled                  = try(var.log_publishing_options["application_logs_enabled"], false)
      log_type                 = "ES_APPLICATION_LOGS"
      cloudwatch_log_group_arn = try(var.log_publishing_options["application_logs_cw_log_group_arn"], null)
    }
  }

  dynamic "log_publishing_options" {
    for_each = try(var.log_publishing_options["index_logs_enabled"], false) ? [1] : []
    content {
      enabled                  = try(var.log_publishing_options["index_logs_enabled"], false)
      log_type                 = "INDEX_SLOW_LOGS"
      cloudwatch_log_group_arn = try(var.log_publishing_options["index_logs_cw_log_group_arn"], null)
    }
  }

  dynamic "log_publishing_options" {
    for_each = try(var.log_publishing_options["search_logs_enabled"], false) ? [1] : []
    content {
      enabled                  = try(var.log_publishing_options["search_logs_enabled"], false)
      log_type                 = "SEARCH_SLOW_LOGS"
      cloudwatch_log_group_arn = try(var.log_publishing_options["search_logs_cw_log_group_arn"], null)
    }
  }


  ebs_options {
    ebs_enabled = var.ebs_enabled
    iops        = var.iops
    throughput  = var.throughput
    volume_size = var.volume_size
    volume_type = var.volume_type
  }

  node_to_node_encryption {
    enabled = var.node_to_node_encryption
  }

  access_policies = var.access_policy == null && var.default_policy_for_fine_grained_access_control ? (<<CONFIG
   {
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": "es:*",
      "Resource": "arn:aws:es:${var.region}:${var.id}:domain/${var.domain_name}/*"
    }
  ]
}
    CONFIG 
  ) : var.access_policy
  

  domain_endpoint_options {
    enforce_https                   = var.domain_endpoint_options_enforce_https
    custom_endpoint_enabled         = var.custom_endpoint_enabled
    custom_endpoint                 = var.custom_endpoint_enabled ? var.custom_endpoint : null
    custom_endpoint_certificate_arn = var.custom_endpoint_enabled ? var.custom_endpoint_certificate_arn : null
    tls_security_policy             = var.tls_security_policy
  }
  tags       = var.tags
  #depends_on = [aws_iam_service_linked_role.os, time_sleep.role_dependency]
}

resource "aws_elasticsearch_domain_saml_options" "opensearch" {
  count       = var.saml_enabled ? 1 : 0
  domain_name = var.name

  saml_options {
    enabled                 = true
    subject_key             = var.saml_subject_key
    roles_key               = var.saml_roles_key
    session_timeout_minutes = var.saml_session_timeout
    master_user_name        = var.saml_master_user_name
    master_backend_role     = var.saml_master_backend_role

    idp {
      entity_id        = var.saml_entity_id
      metadata_content = file("./metadata.xml")
    }
  }
}

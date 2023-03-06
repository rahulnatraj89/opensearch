variable "region" {
  description = "AWS region."
  type        = string
  default     = ""
}

variable "engine_version" {
  description = "Engine version of elasticsearch."
  type        = string
  default     = "OpenSearch_2.3"
}

variable "name" {
  description = "Name of OpenSerach domain and sufix of all other resources."
  type        = string
  default     = ""
}
variable "replicaname" {
  description = "Name of OpenSerach domain and sufix of all other resources."
  type        = string
  default     = ""
}
variable "master_user_arn" {
  description = "Name of OpenSerach domain and sufix of all other resources."
  type        = string
  default     = ""
}
variable "master_user_name" {
  description = "Name of OpenSerach domain and sufix of all other resources."
  type        = string
  default     = ""
}


variable "instance_type" {
  description = "Instance type."
  type        = string
  default     = "r6g.large.search"
}

variable "warm_count" {
  description = "Instance type."
  type        = string
  default     = 3
}
variable "warm_type" {
  description = "Instance type."
  type        = string
  default     = "ultrawarm1.large.search"
}

variable "domain_endpoint_options_enforce_https" {
  description = "Enforce https."
  type        = bool
  default     = true
}


variable "custom_endpoint_enabled" {
  description = "If custom endpoint is enabled."
  type        = bool
  default     = false
}

variable "custom_endpoint" {
  description = "Custom endpoint https."
  type        = string
  default     = ""
}

variable "custom_endpoint_certificate_arn" {
  description = "Custom endpoint certificate."
  type        = string
  default     = null
}

variable "volume_size" {
  description = "Volume size of ebs storage."
  type        = number
  default     = 200
}

variable "volume_type" {
  description = "Volume type of ebs storage."
  type        = string
  default     = "gp3"
}

variable "access_policy" {
  description = "Access policy to OpenSearch. If `default_policy_for_fine_grained_access_control` is enabled, this policy would be overwritten."
  type        = string
  default     = null
}

variable "tls_security_policy" {
  description = "TLS security policy."
  type        = string
  default     = "Policy-Min-TLS-1-2-2019-07"
}

variable "vpc" {
  description = "VPC ID"
  type        = string
  default     = ""
}

variable "subnet_ids" {
  description = "CIDS blocks of subnets."
  type        = list(string)
  default     = ["",""]
  }

variable "inside_vpc" {
  description = "Openserach inside VPC."
  type        = bool
  default     = true
}

variable "cognito_enabled" {
  description = "Cognito authentification enabled for OpenSearch."
  type        = bool
  default     = false
}

variable "advanced_security_options_enabled" {
  type        = bool
  description = "If advanced security options is enabled."
  default     = true
}


variable "identity_pool_id" {
  type        = string
  description = "Cognito identity pool id."
  default     = ""
}

variable "user_pool_id" {
  type        = string
  description = "Cognito user pool id."
  default     = ""
}

variable "cognito_role_arn" {
  type        = string
  description = "Cognito role ARN. We need to enable `advanced_security_options_enabled`."
  default     = ""
}


variable "implicit_create_cognito" {
  type        = bool
  description = "Cognito will be created inside module. It this is not enables and we want cognito authentication, we need to create cognito resources outside of module."
  default     = true
}

variable "internal_user_database_enabled" {
  type        = bool
  description = "Internal user database enabled. This should be enabled if we want authentication with master username and master password."
  default     = false
}


variable "create_a_record" {
  type        = bool
  description = "Create A record for custom domain."
  default     = true
}

variable "ebs_enabled" {
  type        = bool
  description = "EBS enabled"
  default     = true
}

variable "aws_service_name_for_linked_role" {
  type        = string
  description = "AWS service name for linked role."
  default     = "opensearchservice.amazonaws.com"
}


variable "default_policy_for_fine_grained_access_control" {
  type        = bool
  description = "Default policy for fine grained access control would be created."
  default     = true
}

variable "advanced_options" {
  description = "Key-value string pairs to specify advanced configuration options."
  type        = map(string)
  default     = {"rest.action.multi.allow_explicit_index"= "true"}
}

variable "iops" {
  description = "Baseline input/output (I/O) performance of EBS volumes attached to data nodes."
  type        = number
  default     = 3000
}

variable "throughput" {
  description = "Specifies the throughput."
  type        = number
  default     = 250
}

variable "cluster_config" {
  description = "Auto tune options from documentation."
  type        = any
  default     = {}
}

variable "encrypt_at_rest" {
  description = "Encrypt at rest."
  type        = any
  default     = {}
}

variable "log_publishing_options" {
  description = "Encrypt at rest."
  type        = any
  default     = {}
}

variable "node_to_node_encryption" {
  type        = bool
  description = "Is node to node encryption enabled."
  default     = true
}

variable "tags" {
  description = "Tags."
  type        = map(any)
  default     = {environment = ""
                name         = ""
                program	     = ""
                project      = "" }
}


variable "saml_enabled" {
  description = "Indicates whether to configure SAML for the OpenSearch dashboard."
  type        = bool
  default     = true
}

variable "saml_subject_key" {
  description = "Element of the SAML assertion to use for username."
  type        = string
  default     = ""
}

variable "saml_roles_key" {
  description = "Element of the SAML assertion to use for backend roles."
  type        = string
  default     = ""
}

variable "saml_entity_id" {
  description = "The unique Entity ID of the application in SAML Identity Provider."
  type        = string
  default     = ""
}

variable "saml_metadata_content" {
  description = "The metadata of the SAML application in xml format."
  type        = string
  default     = ""
}

variable "saml_session_timeout" {
  description = "Duration of a session in minutes after a user logs in. Default is 60. Maximum value is 1,440."
  type        = number
  default     = 60
}

variable "saml_master_backend_role" {
  description = "This backend role receives full permissions to the cluster, equivalent to a new master role, but can only use those permissions within Dashboards."
  type        = string
  default     = null
}

variable "saml_master_user_name" {
  description = "This username receives full permissions to the cluster, equivalent to a new master user, but can only use those permissions within Dashboards."
  type        = string
  default     = null
}

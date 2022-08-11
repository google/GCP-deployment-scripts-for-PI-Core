variable "gcp_service_list" {
  description = "List of GCP service to be enabled for a project."
  type        = list(string)
  default     = [
    "compute.googleapis.com",
    "storage-component.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "managedidentities.googleapis.com",
    "secretmanager.googleapis.com",
    "dns.googleapis.com",
    ]
}

variable "project_id" {
  default = "null"
}

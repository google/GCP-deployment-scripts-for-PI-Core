variable "project_id" {
  default = "null"
}

variable "sa_email" {
  default = "null"
}

variable "iam_role" {
  type = list(string)
  default = ["roles/storage.admin","roles/secretmanager.admin","roles/compute.admin","roles/iam.serviceAccountUser"]
}

variable "api_id" {
  default = "null"
}

variable "tf_sa" {
  default = "Null"
}

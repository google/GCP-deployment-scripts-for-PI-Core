provider "google"{
  credentials = file("${var.creds}")
  project = var.project_id
  region = var.region
}

terraform {
  required_version = ">= 0.13"

  required_providers {
    google      = "~> 3.26"
    google-beta = "~> 3.34.0"
    random      = "~> 2.3"
    null        = "~> 2.1"
    tls         = "~> 3.0.0"
    local       = "~> 2.0.0"
  }

  backend "gcs" {
    bucket      = "osi-pi-tfbk"
    prefix      = "osi-tfsate"
    credentials = "creds.json"
  }

}

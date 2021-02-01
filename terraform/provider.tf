# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

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

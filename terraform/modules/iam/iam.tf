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

##############################
## Service Account Creation ##
##############################
resource "google_service_account" "osi-pi-sa" {
    account_id   = "osi-pi-sa"
    display_name = "osi-pi-sa"
    project      = var.project_id
}


########################
## Addind roles to SA ##
########################
resource "google_project_iam_member" "project" {
  count   = length(var.iam_role)

  project = var.project_id
  role    = "${element(var.iam_role,count.index)}"
  member  = "serviceAccount:${var.sa_email}"
}


#####################
## Output SA Email ##
#####################
output "sa-out"{
  value = google_service_account.osi-pi-sa.email
}

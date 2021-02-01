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

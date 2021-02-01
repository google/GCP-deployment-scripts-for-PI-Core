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

variable "ad-dn" {
  default = "osi-pi-test.com"
}

variable "vpc-out"{
  default = "null"
}

variable "ad-cidr"{
  default = "172.16.0.0/20"
}

variable "ad-region" {
  default = "null"
}

variable "ad-projectid" {
  default = "null"
}

variable "ad-secret" {
  default = "null"
}

variable "google-ad" {
  default = "null"
}


variable "secret_id" {
  default = "osi-pi-secret"
}

variable "subnet-out" {
  default = "null"
}

variable "architecture" {
  default = "null"
}

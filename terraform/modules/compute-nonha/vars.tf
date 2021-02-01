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

variable "architecture" {
  default = "null"
}

variable "compute-region" {
  default = "null"
}


variable "compute-multi-subnets" {
  type = map(string)
}


variable "epsec" {
  default = "null"
}

variable "compute-machine-type" {
  type = map(string)
}

variable "ad-dn-compute" {
  default = "null"
}

variable "storage" {
  default = "null"
}

variable "sa" {
  default = "null"
}

variable "vpc" {
  default = "null"
}

variable "security_policy" {
  default = "null"
}

variable "ssl-dn-compute" {
  default = "null"
}

variable "valid_domain" {
  default = "null"
}

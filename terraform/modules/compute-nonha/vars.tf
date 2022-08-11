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

variable "zones" {
  
  type    = list(string)
}

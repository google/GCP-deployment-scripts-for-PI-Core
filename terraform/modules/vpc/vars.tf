
variable "vpc_name" {
  default = "osi-vpc"
}

variable "nw-projectid" {
  default = "null"
}


variable "compute-multi-subnets" {
  type = map(string)
}

variable "compute-multi-cidr" {
  default = "10.0.0.0/20"
}

variable "architecture" {
  default = "null"
}

variable "region_name" {
  default = "null"
}

variable "api_id" {
  default = "null"
}

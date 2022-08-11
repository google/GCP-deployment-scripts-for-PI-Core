## Do not hardcode values below , Keep default as null for to be fetched from TFVars##


variable "ad-dn" {
  default = "null"
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

variable "OS" {
  description = "Please enter OS of your deployment machine"
}

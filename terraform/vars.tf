variable "project_id" {
  description = "Please enter project id for deployment"
}

variable "google_ad" {
  description = "Google Managed AD required? Please enter yes/no"
  default     = "yes"
}

variable "architecture" {
  description = "Please enter HA or Non-HA"

  validation {
    condition     = var.architecture == "HA" || var.architecture == "Non-HA"
    error_message = "The value for architecture is case sensitive, please enter \"HA or Non-HA\"."
  }
}

variable "valid_domain" {
  description = "Please enter Yes or No"

  validation {
    condition     = var.valid_domain == "Yes" || var.valid_domain == "No"
    error_message = "The value for valid_domain is case sensitive, please enter \"Yes or No\"."
  }
}

variable "region" {
  description = "Please enter region for deployment supported by google cloud"
}

variable "zones" {
  description = "Please enter region for deployment supported by google cloud"
  type = list(string)
}


variable "compute-multi-subnets" {
  type = map(string)
  default = {
    0 = "osi-subnet-1"
    1 = "osi-subnet-2"
    2 = "osi-subnet-3"
    3 = "osi-subnet-4"
    4 = "osi-subnet-5"
    5 = "osi-subnet-6"
    6 = "osi-subnet-7"
    7 = "osi-subnet-8"
    8 = "osi-subnet-9"
    9 = "osi-subnet-10"
  }
}


variable "ad-cidr"{
  description = "Please enter CIDR range for Google Managed AD from: 10.0.0.0/20, 172.16.0.0/20, 192.168.0.0/20"

  validation {
    #condition     = var.ad-cidr == "10.0.0.0/20" || var.ad-cidr == "10.1.0.0/20" || var.ad-cidr == "172.16.0.0/20" || var.ad-cidr == "192.168.0.0/20"
    condition    = substr(var.ad-cidr, 0, 3) == "10." || substr(var.ad-cidr, 0, 7) == "172.16." || substr(var.ad-cidr, 0, 8) == "192.168."
    error_message = "The value for ad-cidr must be a valid \"RFC 1918 range\"."
  }
}

variable "compute-multi-cidr" {
  description = "Please enter CIDR range for network from: 10.0.0.0/20, 172.16.0.0/20, 192.168.0.0/20"

  validation {
    #condition     = var.compute-multi-cidr == "10.0.0.0/20" || var.compute-multi-cidr == "10.1.0.0/20" ||  var.compute-multi-cidr == "172.16.0.0/20" || var.compute-multi-cidr == "192.168.0.0/20"
    condition    = substr(var.compute-multi-cidr, 0, 3) == "10." || substr(var.compute-multi-cidr, 0, 7) == "172.16." || substr(var.compute-multi-cidr, 0, 8) == "192.168."
    error_message = "The value for ad-cidr must be a valid \"RFC 1918 range\"."
  }
}

variable "epsec" {
  description = "Please enter events/sec eg: 10000,20000,etc"

  validation {
    condition     = var.epsec == "10000" || var.epsec == "20000"
    error_message = "The value for events per secong must be a valid \"10000 or 20000 \"."
  }
}

variable "compute-machine-type" {
  type = map(string)
  default = {
    10000 = "n2d-standard-2"
    20000 = "n2d-standard-4"
    }
}

variable "ad-dn" {
  description = "Please enter Domain Name eg: test.com"

  validation {
    # regex(...) fails if it cannot find a match
    condition     = can(regex("\\.", var.ad-dn))
    error_message = "The value for ad-dn must be valid, eg: \"test.com\"."
  }
}

variable "storage" {
  description = "Please enter the bucket name conraing the executable files"
}

variable "creds" {
  description = "Please enter the credential file name inside the terraform root directory"
}

variable "tf_sa" {
  description = "Enter email id of the service account use to deploy terraform"
}

variable "ssl-dn" {
  description = "Please Enter a valid public domain/sub-domain name"
}

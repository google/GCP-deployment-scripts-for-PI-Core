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

###############
## GCP Zones ##
###############
data "google_compute_zones" "zones"{
  region     = var.region
  project    = var.project_id
}


###########################
## Add Lables to project ##
###########################
resource "null_resource" "project_lables" {

  provisioner "local-exec" {
    on_failure  = "continue"
    command     = "gcloud alpha projects update ${var.project_id} --update-labels zone1=${data.google_compute_zones.zones.names[0]},zone2=${data.google_compute_zones.zones.names[1]},zone3=${data.google_compute_zones.zones.names[2]} --quiet"
    interpreter = ["PowerShell", "-Command"]
  }
}


#####################################
## Default Compute Service Account ##
#####################################
data "google_compute_default_service_account" "default" {
  project    = var.project_id
}


####################
## Module For IAM ##
####################
module "osi-iam-mod" {
  source     = "./modules/iam"
  project_id = var.project_id
  sa_email   = data.google_compute_default_service_account.default.email
  tf_sa      = var.tf_sa
  depends_on = [null_resource.project_lables]
}


#####################################
## Module For VPC/Subnets/Firewall ##
#####################################
module "osi-vpc-mod" {
  source = "./modules/vpc"
  nw-projectid          = var.project_id
  compute-multi-cidr    = var.compute-multi-cidr
  compute-multi-subnets = var.compute-multi-subnets
  architecture          = var.architecture
  region_name           = var.region
  depends_on            = [module.osi-iam-mod]
}


################################################
## Module For Google Managed Active Directory ##
################################################
module "osi-google-ad-mod" {
  source       = "./modules/google-ad"
  vpc-out      = module.osi-vpc-mod.osi-vpc-out
  subnet-out   = module.osi-vpc-mod.osi-subnet-out
  ad-projectid = var.project_id
  google-ad    = var.google_ad
  ad-cidr      = var.ad-cidr
  ad-dn        = var.ad-dn
  ad-region    = var.region
  architecture = var.architecture
}


###############################
## Module For Compute Non-HA ##
###############################
module "compute-nonha-mod" {
  count = var.architecture == "Non-HA" ? 1 : 0

  source                = "./modules/compute-nonha"
  vpc                   = module.osi-vpc-mod.osi-vpc-out
  project_id            = var.project_id
  architecture          = var.architecture
  compute-multi-subnets = var.compute-multi-subnets
  epsec                 = var.epsec
  compute-machine-type  = var.compute-machine-type
  ad-dn-compute         = var.ad-dn
  storage               = var.storage
  sa                    = data.google_compute_default_service_account.default.email
  security_policy       = google_compute_security_policy.policy.0.id
  compute-region        = var.region
  ssl-dn-compute        = var.ssl-dn
  valid_domain          = var.valid_domain

  depends_on            = [module.osi-google-ad-mod]
}


###########################
## Module For Compute HA ##
###########################
module "compute-ha-mod" {
  count = var.architecture == "Non-HA" ? 0 : 1

  source                = "./modules/compute-ha"
  vpc                   = module.osi-vpc-mod.osi-vpc-out
  project_id            = var.project_id
  architecture          = var.architecture
  compute-multi-subnets = var.compute-multi-subnets
  epsec                 = var.epsec
  compute-machine-type  = var.compute-machine-type
  ad-dn-compute         = var.ad-dn
  storage               = var.storage
  sa                    = data.google_compute_default_service_account.default.email
  security_policy       = google_compute_security_policy.policy.0.id
  compute-region        = var.region
  ssl-dn-compute        = var.ssl-dn

  depends_on            = [module.osi-google-ad-mod]
}


##################
## Cloud Router ##
##################
resource "google_compute_router" "osi-router" {
  count = var.architecture == "Non-HA" ? 1 : 1

  name    = "osi-router"
  region  = var.region
  network = module.osi-vpc-mod.osi-vpc-out

  bgp {
    asn = 64514
  }
}


###############
## Cloud NAT ##
###############
resource "google_compute_router_nat" "osi-nat" {
  count = var.architecture == "Non-HA" ? 1 : 1

  name                               = "osi-nat"
  router                             = google_compute_router.osi-router[count.index].name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}


#################################
## Cloud armor security policy ##
#################################
resource "google_compute_security_policy" "policy" {
  count = var.architecture == "Non-HA" ? 1 : 1

  name = "policy-pivii"
  rule {
    action   = "allow"
    priority = "996"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["182.70.32.239/32"]
      }
    }
    description = "first rule"
  }

  rule {
    action   = "deny(403)"
    priority = "997"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["0.0.0.0/0"]
      }
    }
    description = "second rule"
  }

  rule {
    action   = "deny(404)"
    priority = "998"
    match {
        expr {
          expression = "request.path.matches('(?i:/pivision/admin)')"
        }
      }
    description = "third rule"
  }

  rule {
    action   = "allow"
    priority = "999"
    match {
        expr {
          expression = "request.path.matches('(?i:/pivision/)')"
        }
      }
    description = "fourth rule"
  }

  rule {
    action   = "allow"
    priority = "1000"
    match {
        expr {
          expression = "request.path.matches('(?i:/piwebapi/omf$)')"
        }
      }
    description = "fifth rule"
  }
 
  rule {
    action   = "deny(403)"
    priority = "1001"
    match {
        expr {
          expression = "request.path.matches('(?i:/piwebapi/)')"
        }
      }
    description = "sixth rule"
  }

  rule {
    action   = "deny(403)"
    priority = "2147483647"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "default rule"
  }
}
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

##################
## VPC Creation ##
##################
resource "google_compute_network" "osi-vpc" {
    auto_create_subnetworks = "false"
    name                    = var.vpc_name
    project                 = var.nw-projectid
    routing_mode            = "REGIONAL"
}


#####################
## subnet creation ##
#####################
resource "google_compute_subnetwork" "osi-subnet" {

    count = var.architecture == "Non-HA" ? 3 : 10

    name                     = lookup(var.compute-multi-subnets,count.index)
    ip_cidr_range            = cidrsubnet(var.compute-multi-cidr,4,count.index + 2)
    network                  = google_compute_network.osi-vpc.id
    project                  = var.nw-projectid
    region                   = var.region_name
    private_ip_google_access = true
}


####################
## Firewall Rules ##
####################
resource "google_compute_firewall" "osi-fw" {
  name          = "pi-internal"
  network       = google_compute_network.osi-vpc.name
  project       = var.nw-projectid
  source_ranges = ["${var.compute-multi-cidr}"]
  priority      = "1000"

  allow {
    protocol = "tcp"
    ports    = ["5985"]
  }

  allow {
    protocol = "icmp"
  }

  target_tags = ["osi-internal"]
}

resource "google_compute_firewall" "osi-fw2" {
  name          = "bastion-piweb"
  network       = google_compute_network.osi-vpc.name
  project       = var.nw-projectid
  source_tags = ["bastion"]
  priority      = "900"
  
  allow {
    protocol = "tcp"
    ports    = ["443","444"]
  }

  target_tags = ["osi-web"]


}

resource "google_compute_firewall" "osi-fw3" {
  name          = "bastion-rdp"
  network       = google_compute_network.osi-vpc.name
  project       = var.nw-projectid
  source_tags = ["bastion"]
  priority      = "900"
  
  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }

  target_tags = ["rdp"]


}

resource "google_compute_firewall" "osi-fw4" {
  name          = "iap-compute"
  network       = google_compute_network.osi-vpc.name
  project       = var.nw-projectid
  source_ranges = ["35.235.240.0/20"]
  priority      = "900"
  
  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }

  target_tags = ["iap"]


}

resource "google_compute_firewall" "osi-fw5" {
  name          = "lb-web"
  network       = google_compute_network.osi-vpc.name
  project       = var.nw-projectid
  source_ranges = ["35.191.0.0/16","130.211.0.0/22"]
  priority      = "900"
  
  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  target_tags = ["osi-web"]


}

resource "google_compute_firewall" "osi-fw6" {
  name          = "piclient-piserver"
  network       = google_compute_network.osi-vpc.name
  project       = var.nw-projectid
  source_tags = ["pi-client"]
  priority      = "900"
  
  allow {
    protocol = "tcp"
    ports    = ["5450", "5457"]
  }

  target_tags = ["pi-server"]


}

resource "google_compute_firewall" "osi-fw7" {
  name          = "sqlclient-sqlserver"
  network       = google_compute_network.osi-vpc.name
  project       = var.nw-projectid
  source_tags = ["sql-client"]
  priority      = "900"
  
  allow {
    protocol = "tcp"
    ports    = ["1433"]
  }

  target_tags = ["sql-server"]


}

resource "google_compute_firewall" "osi-fw8" {
  name          = "default-block"
  network       = google_compute_network.osi-vpc.name
  project       = var.nw-projectid
  source_ranges = ["0.0.0.0/0"]
  priority      = "65500"
  
  deny {
    protocol = "all"
  }
  
}

resource "google_compute_firewall" "osi-fw9" {
  count = var.architecture == "Non-HA" ? 0 : 1
  name          = "pi-iscsi-fw"
  network       = google_compute_network.osi-vpc.name
  project       = var.nw-projectid
  source_ranges = ["10.0.0.0/20"]
  priority      = "1000"

  allow {
    protocol = "all"
  }
  target_tags = ["iscsi"]
}


#####################
## Output VPC Name ##
#####################
output "osi-vpc-out"{
  value       = google_compute_network.osi-vpc.id
  description = "VPC-ID for OSI_PI"
}

output "osi-vpc-name"{
  value = google_compute_network.osi-vpc.name
}


#####################
## Output subnet Names ##
#####################
output "osi-subnet-out"{
  value       = google_compute_subnetwork.osi-subnet.*.name
  description = "Subnet name for OSI_PI"
}

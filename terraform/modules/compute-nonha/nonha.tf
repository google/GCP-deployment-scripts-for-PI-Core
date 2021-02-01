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
  region     = var.compute-region
  project    = var.project_id
}


##################
## Image MS SQL ##
##################
data "google_compute_image" "osi-sql-image" {
  family  = "sql-std-2016-win-2016"
  project = "windows-sql-cloud"
}


#################################
## Image Microsoft Server 2016 ##
#################################
data "google_compute_image" "others" {
  family  = "windows-2016"
  project = "windows-cloud"
}


#######################################################
## Non-HA : Compute instance for OSI PI Bastion Host ##
#######################################################
resource "google_compute_instance" "osi3" {
    count = var.architecture == "Non-HA" ? 1 : 0

    name         = "pibastion${count.index+1}"
    description  = "OSI PI Bastion Host"
    project      = var.project_id
    zone         = data.google_compute_zones.zones.names[count.index]
    machine_type = lookup(var.compute-machine-type,var.epsec,10000)
    tags         = ["rdp", "iap", "bastion"]
    boot_disk {
    initialize_params {
      image = data.google_compute_image.others.self_link
      size  = 50
      type  = "pd-standard"
    }
  }

  network_interface {
    network    = var.vpc
    subnetwork = lookup(var.compute-multi-subnets,count.index+2)

    access_config{
      // Ephemeral IP
    }
  }
  metadata = {
    domain-name                = "${var.ad-dn-compute}"
    windows-startup-script-ps1 = file("${path.module}/../../../powershell/non-ha/pibastion.ps1")
    }
  service_account {
      email  = "${var.sa}"
      scopes = ["cloud-platform","storage-rw"]
    }
}


################################################
## Non-HA : Compute instance for OSI PI mssql ##
################################################
resource "google_compute_instance" "osi-pi-mssql" {
    count = var.architecture == "Non-HA" ? 1 : 0

    name         = "pisql-${count.index+1}"
    description  = "OSI PI MS SQL server"
    zone         = data.google_compute_zones.zones.names[count.index]
    project      = var.project_id
    machine_type = lookup(var.compute-machine-type,var.epsec,10000)
    tags         = ["osi-internal", "rdp", "sql-server"]
    boot_disk {
    initialize_params {
      image = data.google_compute_image.osi-sql-image.self_link
      size  = 50
      type  = "pd-standard"
    }
  }
  network_interface {
    network    = var.vpc
    subnetwork = lookup(var.compute-multi-subnets,count.index)
  }
  metadata = {
    domain-name                = "${var.ad-dn-compute}"
    storage                    = "${var.storage}"
    af-server                  = "pisvr01"
    windows-startup-script-ps1 = file("${path.module}/../../../powershell/non-ha/sql.ps1")
    }

  service_account {
    email  = "${var.sa}"
    scopes = ["cloud-platform","storage-rw"]
  }
}


################################################################
## Non-HA : Secondary Disk for PI AF/DA/vision/web/integrator ##
################################################################
resource "google_compute_disk" "disk-osi" {
    count = var.architecture == "Non-HA" ? 2 : 0

    name    = "pi-${count.index+1}"
    project = var.project_id
    type    = "pd-standard"
    zone    = data.google_compute_zones.zones.names[0]
    size    = 50
}


######################################################################
## Non-HA : Compute instance for OSI PI DA/AF/analysis/notification ##
######################################################################
resource "google_compute_instance" "osi1" {
    count = var.architecture == "Non-HA" ? 1 : 0

    name         = "pisvr-1"
    description  = "OSI PI DA/AF/Analysis/Notification"
    project      = var.project_id
    zone         = data.google_compute_zones.zones.names[count.index]
    machine_type = lookup(var.compute-machine-type,var.epsec,10000)
    tags         = ["osi-internal", "pi-server", "rdp", "sql-client"]
    boot_disk {
    initialize_params {
      image = data.google_compute_image.others.self_link
      size  = 50
      type  = "pd-standard"
    }
    }
    attached_disk{
      source      = "${element(google_compute_disk.disk-osi.*.self_link,0)}"
      device_name = "${element(google_compute_disk.disk-osi.*.name,0)}"
      mode        = "READ_WRITE"
    }
    network_interface {
      network    = var.vpc
      subnetwork = lookup(var.compute-multi-subnets,count.index+1)
  }

  metadata = {
    domain-name                = "${var.ad-dn-compute}"
    sql-server                 = "${element(google_compute_instance.osi-pi-mssql.*.name,0)}"
    storage                    = "${var.storage}"
    windows-startup-script-ps1 = file("${path.module}/../../../powershell/non-ha/pisvr.ps1")
    }

  service_account {
      email  = "${var.sa}"
      scopes = ["cloud-platform","storage-rw"]
    }
}


#########################################################################
## Non-HA : Compute instance Template for OSI PI vision/web/integrator ##
#########################################################################
resource "google_compute_instance_template" "it-pivii" {
  count = var.architecture == "Non-HA" ? 1 : 0

  name           = "it-pivii"
  description    = "This template is used to create vision/web/integrator OSI application"
  project        = var.project_id
  region         = var.compute-region
  machine_type   = lookup(var.compute-machine-type,var.epsec,10000)
  tags           = ["osi-internal","osi-web","health-check", "pi-client", "rdp", "sql-client"]
  can_ip_forward = false

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }

  disk {
    source_image = data.google_compute_image.others.self_link
    auto_delete  = true
    boot         = true
    type         = "pd-standard"
    disk_size_gb = 50
  }

  // additional disk resource
  disk {
    // Instance Templates reference disks by name, not self link
    source      = "${element(google_compute_disk.disk-osi.*.name,1)}"
    device_name = "${element(google_compute_disk.disk-osi.*.name,1)}"
    mode        = "READ_WRITE"
    auto_delete = false
    boot        = false
  }

  network_interface {
    network    = var.vpc
    subnetwork = lookup(var.compute-multi-subnets,count.index+2)
  }

  metadata = {
    domain-name                = "${var.ad-dn-compute}"
    af-server                  = "${element(google_compute_instance.osi1.*.name,0)}"
    sql-server                 = "${element(google_compute_instance.osi-pi-mssql.*.name,0)}"
    storage                    = "${var.storage}"
    windows-startup-script-ps1 = file("${path.module}/../../../powershell/non-ha/pivii.ps1")
    }

  service_account {
      email  = "${var.sa}"
      scopes = ["cloud-platform","storage-rw"]
    }
}


###################################################
## Non-HA : MIG for OSI PI vision/web/integrator ##
###################################################
resource "google_compute_instance_group_manager" "mig-pivii" {
  count = var.architecture == "Non-HA" ? 1 : 0

  name               = "mig-pivii"
  base_instance_name = "pivii"
  project            = var.project_id
  zone               = data.google_compute_zones.zones.names[count.index]
  target_size        = 1

  named_port {
    name = "https"
    port = 443
  }

  version {
    instance_template  = "${element(google_compute_instance_template.it-pivii.*.id,count.index)}"
  }

  # auto_healing_policies {
  #   health_check      = "${element(google_compute_health_check.hc-daaf.*.id,0)}"
  #   initial_delay_sec = 300
  # }
}


############################################################
## Non-HA : Health Check for OSI PI vision/web/integrator ##
############################################################
resource "google_compute_https_health_check" "hc-pivii" {
  count = var.architecture == "Non-HA" ? 1 : 0

  name                = "hc-pivii"
  project             = var.project_id
  request_path        = "/"
  check_interval_sec  = 120
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 5
  port                = "443"

}


###############################################################
## Non-HA : Backend Service for OSI PI vision/web/integrator ##
###############################################################
resource "google_compute_backend_service" "bk-pivii" {
  count = var.architecture == "Non-HA" ? 1 : 0

  name                            = "bk-pivii"
  project                         = var.project_id
  load_balancing_scheme           = "EXTERNAL"
  port_name                       = "https"
  protocol                        = "HTTPS"
  timeout_sec                     = 15
  connection_draining_timeout_sec = 10
  health_checks                   = [google_compute_https_health_check.hc-pivii.0.id]
  # security_policy                 = google_compute_security_policy.policy.0.id
  security_policy                 = var.security_policy

  backend {
    group = google_compute_instance_group_manager.mig-pivii[0].instance_group
  }

}


#######################################################
## Non-HA : URL Map for OSI PI vision/web/integrator ##
#######################################################
resource "google_compute_url_map" "um-pivii" {
  count = var.architecture == "Non-HA" ? 1 : 0

  project         = var.project_id
  name            = "url-map-pivii"
  default_service = google_compute_backend_service.bk-pivii[count.index].id

}


#Following 2 resources generate google managed certificate if the user has valid domain

##########################################################################
## Non-HA : Google managed certificate for OSI PI vision/web/integrator ##
##########################################################################
resource "google_compute_managed_ssl_certificate" "default" {
  count    = var.valid_domain == "Yes" ? 1 : 0
  provider = google-beta

  name     = "osi-cert"
  project  = var.project_id

  managed {
    domains = ["${var.ssl-dn-compute}"]
  }

}


##########################################################
## Non-HA : HTTP Proxy for OSI PI vision/web/integrator ##
##########################################################
resource "google_compute_target_https_proxy" "proxy-pivii" {
  count    = var.valid_domain == "Yes" ? 1 : 0

  name             = "proxy-pivii"
  url_map          = google_compute_url_map.um-pivii[count.index].id
  ssl_certificates = [element(google_compute_managed_ssl_certificate.default.*.id,count.index)]

}



##################################################################
## Non-HA : Creating private keys for self signed certificate ##
##################################################################
resource "tls_private_key" "self_private" {
  count    = var.valid_domain == "No" ? 1 : 0
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
 
}
resource "local_file" "self_key" {
  count    = var.valid_domain == "No" ? 1 : 0
  content  = tls_private_key.self_private[count.index].private_key_pem
  filename = "${path.module}/certs/self_key.pem"
}


################################################
## Non-HA : Creating self signed certificate ##
################################################
resource "tls_self_signed_cert" "self_cert" {
  count    = var.valid_domain == "No" ? 1 : 0
  key_algorithm     = "ECDSA"
  private_key_pem   = tls_private_key.self_private[count.index].private_key_pem
 

  subject {
    common_name         = "34.120.179.107"
    organization        = "Acme Self Signed"
    organizational_unit = "acme"
  }

  validity_period_hours = 87659
  
  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]
}
resource "local_file" "self_cert_file" {
  count    = var.valid_domain == "No" ? 1 : 0
  content  = tls_self_signed_cert.self_cert[count.index].cert_pem
  filename = "${path.module}/certs/self_cert.pem"
}


####################################################################################
## Non-HA : Generating self signed certificate for OSI PI vision/web/integrator ##
####################################################################################

resource "google_compute_ssl_certificate" "default" {
  count    = var.valid_domain == "No" ? 1 : 0
  

  name     = "osi-cert"
  project  = var.project_id

  private_key = tls_private_key.self_private[count.index].private_key_pem
  certificate = tls_self_signed_cert.self_cert[count.index].cert_pem

  lifecycle {
    create_before_destroy = true
  }

}


#################################################################################
## Non-HA : HTTPS Proxy for OSI PI vision/web/integrator with self signed cert ##
#################################################################################
resource "google_compute_target_https_proxy" "proxy-pivii2" {
  count    = var.valid_domain == "No" ? 1 : 0

  name             = "proxy-pivii2"
  url_map          = google_compute_url_map.um-pivii[count.index].id
  ssl_certificates = [element(google_compute_ssl_certificate.default.*.id,count.index)]

}

###########################################
## Non-HA : External IP for Loadbalancer ##
###########################################
resource "google_compute_global_address" "default" {
  count = var.architecture == "Non-HA" ? 1 : 0

  name = "static-osipi"
}


#########################################################################################
## Non-HA : Global forwarding rule for OSI PI vision/web/integrator for managed cert
########################################################################################
resource "google_compute_global_forwarding_rule" "fwd-pivii" {
  count    = var.valid_domain == "Yes" ? 1 : 0

  name                  = "fwd-pivii"
  project               = var.project_id
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL"
  port_range            = "443"
  target                = google_compute_target_https_proxy.proxy-pivii[count.index].id
  ip_address            = google_compute_global_address.default.0.address

}



#########################################################################################
## Non-HA : Global forwarding rule for OSI PI vision/web/integrator for self signed cert
#########################################################################################
resource "google_compute_global_forwarding_rule" "fwd-pivii2" {
  count    = var.valid_domain == "No" ? 1 : 0

  name                  = "fwd-pivii2"
  project               = var.project_id
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL"
  port_range            = "443"
  target                = google_compute_target_https_proxy.proxy-pivii2[count.index].id
  ip_address            = google_compute_global_address.default.0.address

}


#####################################
## Non-HA : Output Loadbalancer IP ##
#####################################
output "lb-ip"{
  value       = google_compute_global_address.default.0.address
  description = "Add the given ip address as an A record under your DNS provider"
}

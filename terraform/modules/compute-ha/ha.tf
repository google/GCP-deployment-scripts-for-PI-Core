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
## Image Microsoft Server 2019 ## changed from 2016
#################################
data "google_compute_image" "others" {
  family  = "windows-2019"
  project = "windows-cloud"
}



###################################################
## HA : Compute instance for OSI PI Bastion Host ##
###################################################
resource "google_compute_instance" "osi-bastion" {
    count = var.architecture == "Non-HA" ? 0 : 2

    name         = "pibastion${count.index+1}"
    description  = "OSI PI Bastion Host"
    project      = var.project_id
    # zone         = data.google_compute_zones.zones.names[count.index]
    zone         = var.zones[count.index]
    machine_type = lookup(var.compute-machine-type,var.epsec,10000)
    tags         = ["iap", "bastion", "pi-anno", "pi-client"]
    boot_disk {
    initialize_params {
      image = data.google_compute_image.others.self_link
      size  = 50
      type  = "pd-standard"
    }
  }

  network_interface {
    network    = var.vpc
    subnetwork = lookup(var.compute-multi-subnets,6)

    access_config{
      // Ephemeral IP
    }
  }
  metadata = {
    domain-name                = "${var.ad-dn-compute}"
    windows-startup-script-ps1 = file("${path.module}/../../../powershell/ha/pibastion1.ps1")
    }
  service_account {
      email  = "${var.sa}"
      scopes = ["cloud-platform","storage-rw"]
    }

}



####################################
## Static internal ip for MSSQL-1 ##
####################################
resource "google_compute_address" "mssql_address" {
  count = var.architecture == "Non-HA" ? 0 : 3

  name         = "mssql-${count.index+1}"
  subnetwork   = lookup(var.compute-multi-subnets,0)
  address_type = "INTERNAL"
  project      = var.project_id
  region       = var.compute-region
}


####################################
## Static internal ip for MSSQL-2 ##
####################################
resource "google_compute_address" "mssql_address1" {
  count = var.architecture == "Non-HA" ? 0 : 3

  name         = "mssql-${count.index+4}"
  subnetwork   = lookup(var.compute-multi-subnets,1)
  address_type = "INTERNAL"
  project      = var.project_id
  region       = var.compute-region
}


##############################################
## HA : Compute instance for OSI PI mssql-2 ##
##############################################
resource "google_compute_instance" "osi-pi-mssql1" {
    count = var.architecture == "Non-HA" ? 0 : 1

    name         = "pimssql${count.index+2}"
    description  = "OSI PI MS SQL server"
    # zone         = data.google_compute_zones.zones.names[count.index+1]
    zone         = var.zones[count.index+1]
    project      = var.project_id
    machine_type = lookup(var.compute-machine-type,var.epsec,10000)
    tags         = ["rdp", "osi-internal", "sql-server", "sql-cluster"]
    boot_disk {
    initialize_params {
      image = data.google_compute_image.osi-sql-image.self_link
      size  = 50
      type  = "pd-standard"
    }
  }
  network_interface {
    network    = var.vpc
    subnetwork = lookup(var.compute-multi-subnets,count.index+1)
    network_ip = google_compute_address.mssql_address1.0.address

    alias_ip_range{
      ip_cidr_range = "${google_compute_address.mssql_address1.1.address}"
    }
    alias_ip_range{
      ip_cidr_range = "${google_compute_address.mssql_address1.2.address}"
    }
  }
  metadata = {
    domain-name                = "${var.ad-dn-compute}"
    storage                    = "${var.storage}"
    windows-startup-script-ps1 = file("${path.module}/../../../powershell/ha/sql2.ps1")
    }

  service_account {
    email  = "${var.sa}"
    scopes = ["cloud-platform","storage-rw"]
  }
  depends_on = [google_compute_instance.osi-bastion]
}


##############################################
## HA : Compute instance for OSI PI mssql-1 ##
##############################################
resource "google_compute_instance" "osi-pi-mssql" {
    count = var.architecture == "Non-HA" ? 0 : 1

    name         = "pimssql${count.index+1}"
    description  = "OSI PI MS SQL server"
    # zone         = data.google_compute_zones.zones.names[count.index]
    zone         = var.zones[count.index]
    project      = var.project_id
    machine_type = lookup(var.compute-machine-type,var.epsec,10000)
    tags         = ["rdp", "osi-internal", "sql-server", "sql-cluster"]
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
    network_ip = google_compute_address.mssql_address.0.address

    alias_ip_range{
      ip_cidr_range = "${google_compute_address.mssql_address.1.address}"
    }
    alias_ip_range{
      ip_cidr_range = "${google_compute_address.mssql_address.2.address}"
    }
  }
  metadata = {
    domain-name                = "${var.ad-dn-compute}"
    storage                    = "${var.storage}"
    ipWSFC1                    = "${google_compute_address.mssql_address.1.address}"
    ipWSFC2                    = "${google_compute_address.mssql_address1.1.address}"
    witness                    = "${google_compute_address.mssql_address2.0.address}"
    ipWSListener1              = "${google_compute_address.mssql_address.2.address}"
    ipWSListener2              = "${google_compute_address.mssql_address1.2.address}"
    windows-startup-script-ps1 = file("${path.module}/../../../powershell/ha/sql1.ps1")
    }

  service_account {
    email  = "${var.sa}"
    scopes = ["cloud-platform","storage-rw"]
  }
  depends_on = [google_compute_instance.osi-pi-mssql1]
}


####################################################################
## HA : Secondary Disk for PI AF/DA/vision/web/integrator - ZONE1 ##
####################################################################
resource "google_compute_disk" "disk-osi" {
    count = var.architecture == "Non-HA" ? 0 : 2

    name    = "disk-daaf-${count.index+1}"
    project = var.project_id
    type    = "pd-standard"
    # zone    = data.google_compute_zones.zones.names[0]
    zone    = var.zones[0]
    size    = 50
}


####################################################################
## HA : Secondary Disk for PI AF/DA/vision/web/integrator - ZONE2 ##
####################################################################
resource "google_compute_disk" "disk-osi1" {
    count = var.architecture == "Non-HA" ? 0 : 2

    name    = "disk-daaf-${count.index+4}"
    project = var.project_id
    type    = "pd-standard"
    # zone    = data.google_compute_zones.zones.names[1]
    zone    = var.zones[1]
    size    = 50
}
  
#   # External disk add

resource "google_compute_disk" "disk-osi6" {
    count = var.architecture == "Non-HA" ? 0 : 1
    name  = "disk-pivii-${count.index+1}"
    project = var.project_id
    zone  = var.zones[0]
    size    = 50
    type    = "pd-standard"
}

resource "google_compute_disk" "disk-osi7" {
    count = var.architecture == "Non-HA" ? 0 : 1
    name  = "disk-pivii-${count.index+2}"
    project = var.project_id
    zone  = var.zones[1]
    size    = 50
    type    = "pd-standard"
}

resource "google_compute_disk" "disk-osi8" {
    count = var.architecture == "Non-HA" ? 0 : 1
    name  = "disk-womf-${count.index+1}"
    project = var.project_id
    zone  = var.zones[0]
    size    = 50
    type    = "pd-standard"
}
resource "google_compute_disk" "disk-osi9" {
    count = var.architecture == "Non-HA" ? 0 : 1
    name  = "disk-womf-${count.index+2}"
    project = var.project_id
    zone  = var.zones[1]
    size    = 50
    type    = "pd-standard"
}

########################################
## HA : Health Check for OSI PI Af/DA ##
########################################
resource "google_compute_health_check" "hc-daaf" {
  count = var.architecture == "Non-HA" ? 0 : 1

  name        = "hc-daaf"
  description = "Health check via tcp"

  timeout_sec         = 5
  check_interval_sec  = 5
  healthy_threshold   = 4
  unhealthy_threshold = 5

  tcp_health_check {
    port = "5457"
  }
}



#############################################################
## HA : Compute instance Template for OSI PI AF/DA - ZONE1 ##
#############################################################
resource "google_compute_instance_template" "it-osi-pi-daaf" {
  count = var.architecture == "Non-HA" ? 0 : 1

  name           = "it-pisvr-${count.index+1}"
  description    = "This template is used to create AF/DA OSI application"
  project        = var.project_id
  machine_type   = lookup(var.compute-machine-type,var.epsec,10000)
  tags           = ["rdp", "osi-internal", "health-check", "pi-server", "sql-client"]
  can_ip_forward = false

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }

  disk {
    source_image = data.google_compute_image.others.self_link
    auto_delete  = false
    boot         = true
    type         = "pd-standard"
    disk_size_gb = 50
  }

  disk {
    // Instance Templates reference disks by name, not self link
    source      = "${element(google_compute_disk.disk-osi.*.name,count.index)}"
    device_name = "${element(google_compute_disk.disk-osi.*.name,count.index)}"
    mode        = "READ_WRITE"
    auto_delete = true
    #type = "PERSISTENT"
    boot        = false
  }

  network_interface {
    network    = var.vpc
    subnetwork = lookup(var.compute-multi-subnets,count.index+5)
  }

  metadata = {
    domain-name                = "${var.ad-dn-compute}"
    storage                    = "${var.storage}"
    windows-startup-script-ps1 = file("${path.module}/../../../powershell/ha/piafda1.ps1")
    }

  service_account {
      email  = "${var.sa}"
      scopes = ["cloud-platform","storage-rw"]
    }
  depends_on = [google_compute_instance.osi-pi-mssql]
}


#############################################################
## HA : Compute instance Template for OSI PI AF/DA - ZONE2 ##
#############################################################
resource "google_compute_instance_template" "it-osi-pi-daaf1" {
  count = var.architecture == "Non-HA" ? 0 : 1

  name           = "it-pisvr-${count.index+2}"
  description    = "This template is used to create AF/DA OSI application"
  project        = var.project_id
  machine_type   = lookup(var.compute-machine-type,var.epsec,10000)
  tags           = ["rdp", "osi-internal", "health-check", "pi-server", "sql-client"]
  can_ip_forward = false

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }

  disk {
    source_image = data.google_compute_image.others.self_link
    auto_delete  = false
    boot         = true
    type         = "pd-standard"
    disk_size_gb = 50
  }

  disk {
    // Instance Templates reference disks by name, not self link
    source      = "${element(google_compute_disk.disk-osi1.*.name,count.index)}"
    device_name = "${element(google_compute_disk.disk-osi1.*.name,count.index)}"
    mode        = "READ_WRITE"
    auto_delete = true
    boot        = false
  }



  network_interface {
    network    = var.vpc
    subnetwork = lookup(var.compute-multi-subnets,count.index+5)
  }

  metadata = {
    domain-name                = "${var.ad-dn-compute}"
    storage                    = "${var.storage}"
    windows-startup-script-ps1 = file("${path.module}/../../../powershell/ha/piafda1.ps1")
    }

  service_account {
      email  = "${var.sa}"
      scopes = ["cloud-platform","storage-rw"]
    }
  depends_on = [google_compute_instance.osi-pi-mssql]
}



################################################
## HA : Regional MIG for OSI PI AF/DA - ZONE1 ##
################################################
resource "google_compute_region_instance_group_manager" "mig-osi-pi-daaf" {
  count = var.architecture == "Non-HA" ? 0 : 1

  name                       = "mig-pisvr-${count.index+1}"
  base_instance_name         = "pisvr${count.index+1}"
  region                     = var.compute-region
  project                    = var.project_id
  # distribution_policy_zones  = ["${data.google_compute_zones.zones.names[count.index]}"]
  distribution_policy_zones  = ["${var.zones[count.index]}"]

  version {
    instance_template  = "${element(google_compute_instance_template.it-osi-pi-daaf.*.id,count.index)}"
  }

  target_size  = 1

  dynamic "stateful_disk" {
    for_each = var.stateful_disks
    content {
     device_name = stateful_disk.value
     delete_rule = "ON_PERMANENT_INSTANCE_DELETION"
  }
  }

  dynamic "update_policy" {
    for_each = var.update_policy
    content {
      instance_redistribution_type = lookup(update_policy.value, "instance_redistribution_type", null)
      max_surge_percent            = lookup(update_policy.value, "max_surge_percent", null)
      max_unavailable_fixed        = lookup(update_policy.value, "max_unavailable_fixed", null)
      replacement_method           = lookup(update_policy.value, "replacement_method", null)
      min_ready_sec                = lookup(update_policy.value, "min_ready_sec", null)
      minimal_action               = update_policy.value.minimal_action
      type                         = update_policy.value.type
    }
  }
}


################################################
## HA : Regional MIG for OSI PI AF/DA - ZONE2 ##
################################################
resource "google_compute_region_instance_group_manager" "mig-osi-pi-daaf1" {
  count = var.architecture == "Non-HA" ? 0 : 1

  name                       = "mig-pisvr-${count.index+2}"
  base_instance_name         = "pisvr${count.index+2}"
  region                     = var.compute-region
  project                    = var.project_id
  # distribution_policy_zones  = ["${data.google_compute_zones.zones.names[count.index+1]}"]
  distribution_policy_zones  = ["${var.zones[count.index+1]}"]

  version {
    instance_template  = "${element(google_compute_instance_template.it-osi-pi-daaf1.*.id,count.index)}"
  }
  

  target_size  = 1

  dynamic "stateful_disk" {
    for_each = var.stateful_disks1
    content {
     device_name = stateful_disk.value
     delete_rule = "ON_PERMANENT_INSTANCE_DELETION"
  }
  }

  dynamic "update_policy" {
    for_each = var.update_policy1
    content {
      instance_redistribution_type = lookup(update_policy.value, "instance_redistribution_type", null)
      max_surge_percent            = lookup(update_policy.value, "max_surge_percent", null)
      max_unavailable_fixed        = lookup(update_policy.value, "max_unavailable_fixed", null)
      replacement_method           = lookup(update_policy.value, "replacement_method", null)
      min_ready_sec                = lookup(update_policy.value, "min_ready_sec", null)
      minimal_action               = update_policy.value.minimal_action
      type                         = update_policy.value.type
    }
  }
}


####################################################
## HA : Regional Backend Service for OSI PI AF/DA ##
####################################################
resource "google_compute_region_backend_service" "bk-daaf" {
  count = var.architecture == "Non-HA" ? 0 : 1

  name                            = "bk-daaf"
  region                          = var.compute-region
  project                         = var.project_id
  load_balancing_scheme           = "INTERNAL"
  # port_name                       = "tcp"
  protocol                        = "TCP"
  timeout_sec                     = 15
  connection_draining_timeout_sec = 10
  health_checks                   = [google_compute_health_check.hc-daaf.0.id]

  backend {
    group           = google_compute_region_instance_group_manager.mig-osi-pi-daaf[0].instance_group
    balancing_mode  = "CONNECTION"
  }

  backend {
    group           = google_compute_region_instance_group_manager.mig-osi-pi-daaf1[0].instance_group
    balancing_mode  = "CONNECTION"
  }
}


#########################################################
## Static internal ip for OSI PI AF/DA TCP Internal LB ##
#########################################################
resource "google_compute_address" "tcpilb_address" {
  count = var.architecture == "Non-HA" ? 0 : 1

  name         = "tcpilb-${count.index+1}"
  subnetwork   = lookup(var.compute-multi-subnets,7)
  address_type = "INTERNAL"
  project      = var.project_id
  region       = var.compute-region
}


###############################################################
## HA : Forwarding rule for OSI PI AF/DA - Internal Frontend ##
###############################################################
resource "google_compute_forwarding_rule" "fwd-daaf" {
  count = var.architecture == "Non-HA" ? 0 : 1

  name                  = "fwd-pisvr-${count.index+1}"
  region                = var.compute-region
  load_balancing_scheme = "INTERNAL"
  ip_address            = element(google_compute_address.tcpilb_address.*.address,count.index)
  ip_protocol           = "TCP"
  backend_service       = element(google_compute_region_backend_service.bk-daaf.*.id,count.index)
  ports                 = ["5457"]
  network               = var.vpc
  subnetwork            = lookup(var.compute-multi-subnets,count.index+7)
  service_label         = "daaf"
}



###################################################################
## HA : Health Check for OSI PI Analysis/Notification/Integrator ##
###################################################################
resource "google_compute_health_check" "hc-ani" {
  count = var.architecture == "Non-HA" ? 0 : 1

  name        = "hc-ani"
  description = "Health check via tcp"

  timeout_sec         = 5
  check_interval_sec  = 5
  healthy_threshold   = 4
  unhealthy_threshold = 5

  tcp_health_check {
    port = "5463"
  }
}



##################################
## Static internal ip for ANI-1 ##
##################################
resource "google_compute_address" "ani_address" {
  count = var.architecture == "Non-HA" ? 0 : 7

  name         = "anione-${count.index+1}"
  subnetwork   = lookup(var.compute-multi-subnets,4)
  address_type = "INTERNAL"
  project      = var.project_id
  region       = var.compute-region
}


##################################
## Static internal ip for ANI-2 ##
##################################
# resource "google_compute_address" "ani_address1" {
#   count = var.architecture == "Non-HA" ? 0 : 3

#   name         = "anitwo-${count.index+1}"
#   subnetwork   = lookup(var.compute-multi-subnets,5)
#   address_type = "INTERNAL"
#   project      = var.project_id
#   region       = var.compute-region
# }


########################################################################################
## HA : Compute instance Template for OSI PI Analysis/Notification/Integrator - ZONE1 ##
########################################################################################
resource "google_compute_instance_template" "it-osi-pi-ani" {
  count = var.architecture == "Non-HA" ? 0 : 1

  name           = "it-ani-${count.index+1}"
  description    = "This template is used to create Analysis/Notification/Integrator application"
  project        = var.project_id
  machine_type   = lookup(var.compute-machine-type,var.epsec,10000)
  tags           = ["rdp", "osi-internal", "health-check", "pi-server", "sql-client", "pi-client", "pianno-cluster", "osi-integrator", "pi-anno"]
  can_ip_forward = false

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }

  disk {
    source_image = data.google_compute_image.others.self_link
    auto_delete  = false
    boot         = true
    type         = "pd-standard"
    disk_size_gb = 50
  }

  disk {
    // Instance Templates reference disks by name, not self link
    source      = "${element(google_compute_disk.disk-osi.*.name,count.index+1)}"
    device_name = "${element(google_compute_disk.disk-osi.*.name,count.index+1)}"
    mode        = "READ_WRITE"
    auto_delete = true
    boot        = false
  }

  network_interface {
    network    = var.vpc
    subnetwork = lookup(var.compute-multi-subnets,count.index+4)
    network_ip = google_compute_address.ani_address.0.address
  }

  metadata = {
    domain-name                = "${var.ad-dn-compute}"
    storage                    = "${var.storage}"
    ilb                        = "${google_compute_address.tcpilb_address.0.address}"
    an1                        = "${google_compute_address.ani_address.0.address}"
    an2                        = "${google_compute_address.ani_address.1.address}"
    ipWSFC1                    = "${google_compute_address.ani_address.2.address}"
    iscsi                      = "${google_compute_address.ani_address.3.address}"
    IPClusRole1                = "${google_compute_address.ani_address.4.address}"
    IPClusRole2                = "${google_compute_address.ani_address.5.address}"
    windows-startup-script-ps1 = file("${path.module}/../../../powershell/ha/piani.ps1")
    }

  service_account {
      email  = "${var.sa}"
      scopes = ["cloud-platform","storage-rw"]
    }
  depends_on = [google_compute_forwarding_rule.fwd-daaf]
}


########################################################################################
## HA : Compute instance Template for OSI PI Analysis/Notification/Integrator - ZONE2 ##
########################################################################################
resource "google_compute_instance_template" "it-osi-pi-ani1" {
  count = var.architecture == "Non-HA" ? 0 : 1

  name           = "it-ani-${count.index+2}"
  description    = "This template is used to create Analysis/Notification/Integrator application"
  project        = var.project_id
  machine_type   = lookup(var.compute-machine-type,var.epsec,10000)
  tags           = ["rdp", "osi-internal", "health-check", "pi-server", "sql-client", "pi-client", "pianno-cluster", "osi-integrator", "pi-anno"]
  can_ip_forward = false

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }

  disk {
    source_image = data.google_compute_image.others.self_link
    auto_delete  = false
    boot         = true
    type         = "pd-standard"
    disk_size_gb = 50
  }

  disk {
    // Instance Templates reference disks by name, not self link
    source      = "${element(google_compute_disk.disk-osi1.*.name,count.index+1)}"
    device_name = "${element(google_compute_disk.disk-osi1.*.name,count.index+1)}"
    mode        = "READ_WRITE"
    auto_delete = true
    boot        = false
  }

  network_interface {
    network    = var.vpc
    subnetwork = lookup(var.compute-multi-subnets,count.index+4)
    network_ip = google_compute_address.ani_address.1.address
  }

  metadata = {
    domain-name                = "${var.ad-dn-compute}"
    storage                    = "${var.storage}"
    an2                        = "${google_compute_address.ani_address.1.address}"
    ilb                        = "${google_compute_address.tcpilb_address.0.address}"
    iscsi                      = "${google_compute_address.ani_address.3.address}"
    windows-startup-script-ps1 = file("${path.module}/../../../powershell/ha/piani.ps1")
    }

  service_account {
      email  = "${var.sa}"
      scopes = ["cloud-platform","storage-rw"]
    }
  depends_on = [google_compute_forwarding_rule.fwd-daaf]
}


###########################################################################
## HA : Regional MIG for OSI PI Analysis/Notification/Integrator - ZONE1 ##
###########################################################################
resource "google_compute_region_instance_group_manager" "mig-osi-pi-ani" {
  count = var.architecture == "Non-HA" ? 0 : 1

  name                       = "mig-ani-${count.index+1}"
  base_instance_name         = "piani${count.index+1}"
  region                     = var.compute-region
  project                    = var.project_id
  # distribution_policy_zones  = ["${data.google_compute_zones.zones.names[count.index]}"]
  distribution_policy_zones  = ["${var.zones[count.index]}"]

  version {
    instance_template  = "${element(google_compute_instance_template.it-osi-pi-ani.*.id,count.index)}"
  }

  target_size  = 1
  dynamic "stateful_disk" {
    for_each = var.stateful_disks2
    content {
     device_name = stateful_disk.value
     delete_rule = "ON_PERMANENT_INSTANCE_DELETION"
  }
  }

  dynamic "update_policy" {
    for_each = var.update_policy2
    content {
      instance_redistribution_type = lookup(update_policy.value, "instance_redistribution_type", null)
      max_surge_percent            = lookup(update_policy.value, "max_surge_percent", null)
      max_unavailable_fixed        = lookup(update_policy.value, "max_unavailable_fixed", null)
      replacement_method           = lookup(update_policy.value, "replacement_method", null)
      min_ready_sec                = lookup(update_policy.value, "min_ready_sec", null)
      minimal_action               = update_policy.value.minimal_action
      type                         = update_policy.value.type
    }
   }
}

###########################################################################
## HA : Regional MIG for OSI PI Analysis/Notification/Integrator - ZONE2 ##
###########################################################################
resource "google_compute_region_instance_group_manager" "mig-osi-pi-ani1" {
  count = var.architecture == "Non-HA" ? 0 : 1

  name                       = "mig-ani-${count.index+2}"
  base_instance_name         = "piani${count.index+2}"
  region                     = var.compute-region
  project                    = var.project_id
  # distribution_policy_zones  = ["${data.google_compute_zones.zones.names[count.index+1]}"]
  distribution_policy_zones  = ["${var.zones[count.index+1]}"]

  version {
    instance_template  = "${element(google_compute_instance_template.it-osi-pi-ani1.*.id,count.index)}"
  }

  target_size  = 1
  dynamic "stateful_disk" {
    for_each = var.stateful_disks3
    content {
     device_name = stateful_disk.value
     delete_rule = "ON_PERMANENT_INSTANCE_DELETION"
  }
  }

  dynamic "update_policy" {
    for_each = var.update_policy3
    content {
      instance_redistribution_type = lookup(update_policy.value, "instance_redistribution_type", null)
      max_surge_percent            = lookup(update_policy.value, "max_surge_percent", null)
      max_unavailable_fixed        = lookup(update_policy.value, "max_unavailable_fixed", null)
      replacement_method           = lookup(update_policy.value, "replacement_method", null)
      min_ready_sec                = lookup(update_policy.value, "min_ready_sec", null)
      minimal_action               = update_policy.value.minimal_action
      type                         = update_policy.value.type
    }
   }
}

###############################################################################
## HA : Regional Backend Service for OSI PI Analysis/Notification/Integrator ##
###############################################################################
resource "google_compute_region_backend_service" "bk-ani" {
  count = var.architecture == "Non-HA" ? 0 : 1

  name                            = "bk-ani"
  region                          = var.compute-region
  project                         = var.project_id
  load_balancing_scheme           = "INTERNAL"
  # port_name                       = "tcp"
  protocol                        = "TCP"
  timeout_sec                     = 15
  connection_draining_timeout_sec = 10
  health_checks                   = [google_compute_health_check.hc-ani.0.id]

  backend {
    group           = google_compute_region_instance_group_manager.mig-osi-pi-ani[0].instance_group
    balancing_mode  = "CONNECTION"
  }

  backend {
    group           = google_compute_region_instance_group_manager.mig-osi-pi-ani1[0].instance_group
    balancing_mode  = "CONNECTION"
  }
}


######################################################################################
## Static internal ip for TCP Internal LB - OSI PI Analysis/Notification/Integrator ##
######################################################################################
# resource "google_compute_address" "tcpilb_address1" {
#   count = var.architecture == "Non-HA" ? 0 : 1

#   name         = "tcpilb-${count.index+2}"
#   subnetwork   = lookup(var.compute-multi-subnets,9)
#   address_type = "INTERNAL"
#   project      = var.project_id
#   region       = var.compute-region
# }


##########################################################################################
## HA : Forwarding rule for OSI PI Analysis/Notification/Integrator - Internal Frontend ##
##########################################################################################
resource "google_compute_forwarding_rule" "fwd-ani-4" {
  count = var.architecture == "Non-HA" ? 0 : 1

  name                  = "fwd-ani-4"
  region                = var.compute-region
  load_balancing_scheme = "INTERNAL"
  ip_address            = "${google_compute_address.ani_address.6.address}"
  ip_protocol           = "TCP"
  backend_service       = element(google_compute_region_backend_service.bk-ani.*.id,count.index)
  ports                 = ["5463","5468"]
  network               = var.vpc
  subnetwork            = lookup(var.compute-multi-subnets,count.index+4)
  service_label         = "ani"
}

#############################################
## Static internal ip for MSSQL-3 witness ##
############################################
resource "google_compute_address" "mssql_address2" {
  count = var.architecture == "Non-HA" ? 0 : 3

  name         = "mssql-${count.index+7}"
  subnetwork   = lookup(var.compute-multi-subnets,1)   #4 
  address_type = "INTERNAL"
  project      = var.project_id
  region       = var.compute-region
}


# ##########################################################################################
# ## HA : Forwarding rule for OSI PI SQL Witness - Internal Frontend ##
# ##########################################################################################
# resource "google_compute_forwarding_rule" "fwd-sql" {
#   count = var.architecture == "Non-HA" ? 0 : 1

#   name                  = "fwd-sql"
#   region                = var.compute-region
#   load_balancing_scheme = "INTERNAL"
#   ip_address            = "${google_compute_address.mssql_address2.2.address}"
#   ip_protocol           = "TCP"
#   backend_service       = element(google_compute_region_backend_service.bk-ani.*.id,count.index)
#   ports                 = ["5463","5468"]
#   network               = var.vpc
#   subnetwork            = lookup(var.compute-multi-subnets,count.index+4)
#   service_label         = "mssql"
# }

# resource "google_compute_forwarding_rule" "fwd-ani" {
#   count = var.architecture == "Non-HA" ? 0 : 1

#   name                  = "fwd-ani-${count.index+1}"
#   region                = var.compute-region
#   load_balancing_scheme = "INTERNAL"
#   ip_address            = "${google_compute_address.ani_address.2.address}"
#   ip_protocol           = "TCP"
#   backend_service       = element(google_compute_region_backend_service.bk-ani.*.id,count.index)
#   ports                 = ["5463","5468"]
#   network               = var.vpc
#   subnetwork            = lookup(var.compute-multi-subnets,count.index+4)
#   service_label         = "ani"
# }

# resource "google_compute_forwarding_rule" "fwd-ani-2" {
#   count = var.architecture == "Non-HA" ? 0 : 1

#   name                  = "fwd-ani-2"
#   region                = var.compute-region
#   load_balancing_scheme = "INTERNAL"
#   ip_address            = "${google_compute_address.ani_address.4.address}"
#   ip_protocol           = "TCP"
#   backend_service       = element(google_compute_region_backend_service.bk-ani.*.id,count.index)
#   ports                 = ["5463","5468"]
#   network               = var.vpc
#   subnetwork            = lookup(var.compute-multi-subnets,count.index+4)
#   service_label         = "ani"
# }

# resource "google_compute_forwarding_rule" "fwd-ani-3" {
#   count = var.architecture == "Non-HA" ? 0 : 1

#   name                  = "fwd-ani-3"
#   region                = var.compute-region
#   load_balancing_scheme = "INTERNAL"
#   ip_address            = "${google_compute_address.ani_address.5.address}"
#   ip_protocol           = "TCP"
#   backend_service       = element(google_compute_region_backend_service.bk-ani.*.id,count.index)
#   ports                 = ["5463","5468"]
#   network               = var.vpc
#   subnetwork            = lookup(var.compute-multi-subnets,count.index+4)
#   service_label         = "ani"
# }

################################################
## HA : Secondary Disk for PI Witness - ZONE3 ##
################################################
resource "google_compute_disk" "disk-osi2" {
    count = var.architecture == "Non-HA" ? 0 : 1

    name    = "disk-witness-${count.index+1}"
    project = var.project_id
    type    = "pd-standard"
    # zone    = data.google_compute_zones.zones.names[2]
    zone    = var.zones[2]
    size    = 50
}


###################################################
## HA : Compute instance for OSI PI Witness ##
###################################################
resource "google_compute_instance" "pi-witness" {
    count = var.architecture == "Non-HA" ? 0 : 1

    name         = "piwitness${count.index+1}"
    description  = "OSI PI Witness"
    # zone         = data.google_compute_zones.zones.names[count.index+2]
    zone         = var.zones[count.index+2]
    project      = var.project_id
    machine_type = lookup(var.compute-machine-type,var.epsec,10000)
    tags         = ["rdp","osi-internal","iscsi", "pi-share"]
    boot_disk {
    initialize_params {
      # image = data.google_compute_image.osi-sql-image.self_link
      image = data.google_compute_image.others.self_link
      size  = 50
      type  = "pd-standard"
    }
    }
    attached_disk{
      source = "${google_compute_disk.disk-osi2.0.name}"
      mode   = "READ_WRITE"
    }

  network_interface {
    network    = var.vpc
    subnetwork = lookup(var.compute-multi-subnets,count.index+4)
    network_ip = google_compute_address.ani_address.3.address
  }
  metadata = {
    domain-name                = "${var.ad-dn-compute}"
    storage                    = "${var.storage}"
    an1                        = "${google_compute_address.ani_address.0.address}"
    an2                        = "${google_compute_address.ani_address.1.address}"
    windows-startup-script-ps1 = file("${path.module}/../../../powershell/ha/iscsi-script.ps1")
    }

  service_account {
    email  = "${var.sa}"
    scopes = ["cloud-platform","storage-rw"]
  }
  depends_on = [google_compute_forwarding_rule.fwd-ani-4]
}


###################################################
## HA : Compute instance for OSI PI SQL Witness ##
###################################################
resource "google_compute_instance" "pi-sql-witness" {
    count = var.architecture == "Non-HA" ? 0 : 1

    name         = "pisqlwitness${count.index+1}"
    description  = "OSI PI SQL Witness"
    # zone         = data.google_compute_zones.zones.names[count.index+2]
    zone         = var.zones[count.index+2]
    project      = var.project_id
    machine_type = lookup(var.compute-machine-type,var.epsec,10000)
    tags         = ["rdp", "osi-internal", "sql-server", "sql-cluster"]
    
    boot_disk {
    initialize_params {
      # image = data.google_compute_image.osi-sql-image.self_link
      image = data.google_compute_image.others.self_link
      size  = 50
      type  = "pd-standard"
    }
    }


  network_interface {
    network    = var.vpc
    subnetwork = lookup(var.compute-multi-subnets,count.index+1) #4
    network_ip = google_compute_address.mssql_address2.0.address 
  
    alias_ip_range{
      ip_cidr_range = "${google_compute_address.mssql_address2.1.address}"
    }
    alias_ip_range{
      ip_cidr_range = "${google_compute_address.mssql_address2.2.address}"
    }
  
  }
  metadata = {
    domain-name                = "${var.ad-dn-compute}"
    storage                    = "${var.storage}"
    sql1                        = "${google_compute_address.mssql_address.0.address}"
    sql2                        = "${google_compute_address.mssql_address1.1.address}"
    windows-startup-script-ps1 = file("${path.module}/../../../powershell/ha/sql-witness-script.ps1")
    }

  service_account {
    email  = "${var.sa}"
    scopes = ["cloud-platform","storage-rw"]
  }
  depends_on = [google_compute_instance.osi-pi-mssql]
}



##################################################################
## HA : Compute instance Template for OSI PI vision/web - ZONE1 ##
##################################################################
resource "google_compute_instance_template" "it-pivii" {
  count = var.architecture == "Non-HA" ? 0 : 1

  name           = "it-vw${count.index+1}"
  project        = var.project_id
  region         = var.compute-region
  machine_type   = lookup(var.compute-machine-type,var.epsec,10000)
  tags           = ["rdp", "osi-internal", "health-check", "osi-web", "pi-client" , "sql-client"]
  can_ip_forward = false

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }

  disk {
    source_image = data.google_compute_image.others.self_link
    auto_delete  = false
    boot         = true
    type         = "pd-standard"
    disk_size_gb = 50
  }

  // additional disk resource
  disk {
    // Instance Templates reference disks by name, not self link
    source      = "${element(google_compute_disk.disk-osi6.*.name,count.index+1)}"
    device_name = "${element(google_compute_disk.disk-osi6.*.name,count.index+1)}"
    mode        = "READ_WRITE"
    auto_delete = true
    boot        = false
    # mode        = "READ_WRITE"
    # auto_delete = true
    # boot        = false
    # type         = "pd-standard"
    # disk_size_gb = 50
  }

  network_interface {
    network    = var.vpc
    subnetwork = lookup(var.compute-multi-subnets,count.index+2)
  }

  metadata = {
    domain-name                = "${var.ad-dn-compute}"
    ilb                        = "${google_compute_address.tcpilb_address.0.address}"
    storage                    = "${var.storage}"
    windows-startup-script-ps1 = file("${path.module}/../../../powershell/ha/pivii.ps1")
    }

  service_account {
      email  = "${var.sa}"
      scopes = ["cloud-platform","storage-rw"]
    }
  depends_on = [google_compute_forwarding_rule.fwd-daaf]
}

#################################################################
## HA : Compute instance Template for OSI PI vision/web -ZONE2 ##
#################################################################
resource "google_compute_instance_template" "it-pivii1" {
  count = var.architecture == "Non-HA" ? 0 : 1

  name           = "it-vw${count.index+2}"
  project        = var.project_id
  region         = var.compute-region
  machine_type   = lookup(var.compute-machine-type,var.epsec,10000)
  tags           = ["rdp", "osi-internal", "health-check", "osi-web", "pi-client" , "sql-client"]
  can_ip_forward = false

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }

  disk {
    source_image = data.google_compute_image.others.self_link
    auto_delete  = false
    boot         = true
    type         = "pd-standard"
    disk_size_gb = 50
  }

  // additional disk resource
  disk {
    // Instance Templates reference disks by name, not self link
    source      = "${element(google_compute_disk.disk-osi7.*.name,count.index+2)}"
    device_name = "${element(google_compute_disk.disk-osi7.*.name,count.index+2)}"
    mode        = "READ_WRITE"
    auto_delete = true
    boot        = false
    # mode        = "READ_WRITE"
    # auto_delete = true
    # boot        = false
    # type         = "pd-standard"
    # disk_size_gb = 50
  }

  network_interface {
    network    = var.vpc
    subnetwork = lookup(var.compute-multi-subnets,count.index+2)
  }

  metadata = {
    domain-name                = "${var.ad-dn-compute}"
    ilb                        = "${google_compute_address.tcpilb_address.0.address}"
    storage                    = "${var.storage}"
    windows-startup-script-ps1 = file("${path.module}/../../../powershell/ha/pivii.ps1")
    }

  service_account {
      email  = "${var.sa}"
      scopes = ["cloud-platform","storage-rw"]
    }
  depends_on = [google_compute_forwarding_rule.fwd-daaf]
}


###############################################################
## HA : Compute instance Template for OSI PI web OMF - ZONE1 ##
###############################################################
resource "google_compute_instance_template" "it-womf" {
  count = var.architecture == "Non-HA" ? 0 : 1

  name           = "it-womf${count.index+1}"
  project        = var.project_id
  region         = var.compute-region
  machine_type   = lookup(var.compute-machine-type,var.epsec,10000)
  tags           = ["rdp", "osi-internal", "health-check", "osi-web", "pi-client" , "sql-client"]
  can_ip_forward = false

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }

  disk {
    source_image = data.google_compute_image.others.self_link
    auto_delete  = false
    boot         = true
    type         = "pd-standard"
    disk_size_gb = 50
  }

  // additional disk resource
  disk {
    // Instance Templates reference disks by name, not self link
    source      = "${element(google_compute_disk.disk-osi8.*.name,count.index+1)}"
    device_name = "${element(google_compute_disk.disk-osi8.*.name,count.index+1)}"
    mode        = "READ_WRITE"
    auto_delete = true
    boot        = false
    # mode        = "READ_WRITE"
    # auto_delete = true
    # boot        = false
    # type         = "pd-standard"
    # disk_size_gb = 50

  }

  network_interface {
    network    = var.vpc
    subnetwork = lookup(var.compute-multi-subnets,count.index+3)
  }

  metadata = {
    domain-name                = "${var.ad-dn-compute}"
    ilb                        = "${google_compute_address.tcpilb_address.0.address}"
    storage                    = "${var.storage}"
    windows-startup-script-ps1 = file("${path.module}/../../../powershell/ha/web-omf.ps1")
    }

  service_account {
      email  = "${var.sa}"
      scopes = ["cloud-platform","storage-rw"]
    }
  depends_on = [google_compute_forwarding_rule.fwd-daaf]
}


###############################################################
## HA : Compute instance Template for OSI PI web OMF - ZONE2 ##
###############################################################
resource "google_compute_instance_template" "it-womf1" {
  count = var.architecture == "Non-HA" ? 0 : 1

  name           = "it-womf${count.index+2}"
  project        = var.project_id
  region         = var.compute-region
  machine_type   = lookup(var.compute-machine-type,var.epsec,10000)
  tags           = ["rdp", "osi-internal", "health-check", "osi-web", "pi-client" , "sql-client"]
  can_ip_forward = false

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }

  disk {
    source_image = data.google_compute_image.others.self_link
    auto_delete  = false
    boot         = true
    type         = "pd-standard"
    disk_size_gb = 50
  }

  // additional disk resource
  disk {
    // Instance Templates reference disks by name, not self link
    source      = "${element(google_compute_disk.disk-osi9.*.name,count.index+2)}"
    device_name = "${element(google_compute_disk.disk-osi9.*.name,count.index+2)}"
    mode        = "READ_WRITE"
    auto_delete = true
    # boot        = false
    # mode        = "READ_WRITE"
    # auto_delete = true
    # boot        = false
    # type         = "pd-standard"
    # disk_size_gb = 50

  }

  network_interface {
    network    = var.vpc
    subnetwork = lookup(var.compute-multi-subnets,count.index+3)
  }

  metadata = {
    domain-name                = "${var.ad-dn-compute}"
    ilb                        = "${google_compute_address.tcpilb_address.0.address}"
    storage                    = "${var.storage}"
    windows-startup-script-ps1 = file("${path.module}/../../../powershell/ha/web-omf.ps1")
    }

  service_account {
      email  = "${var.sa}"
      scopes = ["cloud-platform","storage-rw"]
    }
  depends_on = [google_compute_forwarding_rule.fwd-daaf]
}

############################################
## HA : MIG for OSI PI vision/web - ZONE1 ##
############################################
resource "google_compute_region_instance_group_manager" "mig-pivii" {
  count = var.architecture == "Non-HA" ? 0 : 1

  name                      = "mig-pivii-${count.index+1}"
  base_instance_name        = "pivii${count.index+1}"
  project                   = var.project_id
  region                    = var.compute-region
  # distribution_policy_zones = ["${data.google_compute_zones.zones.names[count.index]}"]
  distribution_policy_zones = ["${var.zones[count.index]}"]
  target_size        = 1

  version {
    instance_template  = "${element(google_compute_instance_template.it-pivii.*.id,count.index)}"
  }

  named_port {
    name = "https"
    port = 443
  }

  dynamic "stateful_disk" {
    for_each = var.stateful_disks4
    content {
     device_name = stateful_disk.value
     delete_rule = "ON_PERMANENT_INSTANCE_DELETION"
  }
  }

  dynamic "update_policy" {
    for_each = var.update_policy4
    content {
      instance_redistribution_type = lookup(update_policy.value, "instance_redistribution_type", null)
      max_surge_percent            = lookup(update_policy.value, "max_surge_percent", null)
      max_unavailable_fixed        = lookup(update_policy.value, "max_unavailable_fixed", null)
      replacement_method           = lookup(update_policy.value, "replacement_method", null)
      min_ready_sec                = lookup(update_policy.value, "min_ready_sec", null)
      minimal_action               = update_policy.value.minimal_action
      type                         = update_policy.value.type
    }
   }

  # auto_healing_policies {
  #   health_check      = "${element(google_compute_https_health_check.hc-pivii.*.id,0)}"
  #   initial_delay_sec = 300
  # }
}


############################################
## HA : MIG for OSI PI vision/web - ZONE2 ##
############################################
resource "google_compute_region_instance_group_manager" "mig-pivii1" {
  count = var.architecture == "Non-HA" ? 0 : 1

  name                      = "mig-pivii-${count.index+2}"
  base_instance_name        = "pivii${count.index+2}"
  project                   = var.project_id
  region                    = var.compute-region
  # distribution_policy_zones = ["${data.google_compute_zones.zones.names[count.index+1]}"]
  distribution_policy_zones = ["${var.zones[count.index+1]}"]
  target_size        = 1

  version {
    instance_template  = "${element(google_compute_instance_template.it-pivii1.*.id,count.index)}"
  }

  named_port {
    name = "https"
    port = 443
  }

dynamic "stateful_disk" {
    for_each = var.stateful_disks5
    content {
     device_name = stateful_disk.value
     delete_rule = "ON_PERMANENT_INSTANCE_DELETION"
  }
  }

  dynamic "update_policy" {
    for_each = var.update_policy5
    content {
      instance_redistribution_type = lookup(update_policy.value, "instance_redistribution_type", null)
      max_surge_percent            = lookup(update_policy.value, "max_surge_percent", null)
      max_unavailable_fixed        = lookup(update_policy.value, "max_unavailable_fixed", null)
      replacement_method           = lookup(update_policy.value, "replacement_method", null)
      min_ready_sec                = lookup(update_policy.value, "min_ready_sec", null)
      minimal_action               = update_policy.value.minimal_action
      type                         = update_policy.value.type
    }
   }
  # auto_healing_policies {
  #   health_check      = "${element(google_compute_https_health_check.hc-pivii.*.id,0)}"
  #   initial_delay_sec = 300
  # }
}

#########################################
## HA : MIG for OSI PI web OMF - ZONE1 ##
#########################################
resource "google_compute_region_instance_group_manager" "mig-womf" {
  count = var.architecture == "Non-HA" ? 0 : 1

  name                      = "mig-womf-${count.index+1}"
  base_instance_name        = "womf${count.index+1}"
  project                   = var.project_id
  region                    = var.compute-region
  # distribution_policy_zones = ["${data.google_compute_zones.zones.names[count.index]}"]
  distribution_policy_zones = ["${var.zones[count.index]}"]
  target_size        = 1

  version {
    instance_template  = "${element(google_compute_instance_template.it-womf.*.id,count.index)}"
  }

  named_port {
    name = "https"
    port = 443
  }
  dynamic "stateful_disk" {
    for_each = var.stateful_disks6
    content {
     device_name = stateful_disk.value
     delete_rule = "ON_PERMANENT_INSTANCE_DELETION"
  }
  }

  dynamic "update_policy" {
    for_each = var.update_policy6
    content {
      instance_redistribution_type = lookup(update_policy.value, "instance_redistribution_type", null)
      max_surge_percent            = lookup(update_policy.value, "max_surge_percent", null)
      max_unavailable_fixed        = lookup(update_policy.value, "max_unavailable_fixed", null)
      replacement_method           = lookup(update_policy.value, "replacement_method", null)
      min_ready_sec                = lookup(update_policy.value, "min_ready_sec", null)
      minimal_action               = update_policy.value.minimal_action
      type                         = update_policy.value.type
    }
   }
  # auto_healing_policies {
  #   health_check      = "${element(google_compute_https_health_check.hc-womf.*.id,0)}"
  #   initial_delay_sec = 300
  # }
}

#########################################
## HA : MIG for OSI PI web OMF - ZONE2 ##
#########################################
resource "google_compute_region_instance_group_manager" "mig-womf1" {
  count = var.architecture == "Non-HA" ? 0 : 1

  name                      = "mig-womf-${count.index+2}"
  base_instance_name        = "womf${count.index+2}"
  project                   = var.project_id
  region                    = var.compute-region
  # distribution_policy_zones = ["${data.google_compute_zones.zones.names[count.index+1]}"]
  distribution_policy_zones = ["${var.zones[count.index+1]}"]
  target_size        = 1

  version {
    instance_template  = "${element(google_compute_instance_template.it-womf1.*.id,count.index)}"
  }

  named_port {
    name = "https"
    port = 443
  }
  dynamic "stateful_disk" {
    for_each = var.stateful_disks7
    content {
     device_name = stateful_disk.value
     delete_rule = "ON_PERMANENT_INSTANCE_DELETION"
  }
  }

  dynamic "update_policy" {
    for_each = var.update_policy7
    content {
      instance_redistribution_type = lookup(update_policy.value, "instance_redistribution_type", null)
      max_surge_percent            = lookup(update_policy.value, "max_surge_percent", null)
      max_unavailable_fixed        = lookup(update_policy.value, "max_unavailable_fixed", null)
      replacement_method           = lookup(update_policy.value, "replacement_method", null)
      min_ready_sec                = lookup(update_policy.value, "min_ready_sec", null)
      minimal_action               = update_policy.value.minimal_action
      type                         = update_policy.value.type
    }
   }
  # auto_healing_policies {
  #   health_check      = "${element(google_compute_https_health_check.hc-womf.*.id,0)}"
  #   initial_delay_sec = 300
  # }
}


#############################################
## HA : Health Check for OSI PI vision/web ##
#############################################
resource "google_compute_https_health_check" "hc-pivii" {
  count = var.architecture == "Non-HA" ? 0 : 1

  name                = "hc-pivii"
  project             = var.project_id
  request_path        = "/"
  check_interval_sec  = 10
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 5
  port = "443"
  
}


##########################################
## HA : Health Check for OSI PI Web OMF ##
##########################################
resource "google_compute_health_check" "hc-womf" {
  count = var.architecture == "Non-HA" ? 0 : 1

  name        = "hc-womf"
  description = "Health check via tcp"

  timeout_sec         = 5
  check_interval_sec  = 120
  healthy_threshold   = 2
  unhealthy_threshold = 5

  tcp_health_check {
    port = "443"
  }
}

################################################
## HA : Backend Service for OSI PI vision/web ##
################################################
resource "google_compute_backend_service" "bk-pivii" {
  count = var.architecture == "Non-HA" ? 0 : 1

  name                            = "bk-pivii"
  project                         = var.project_id
  load_balancing_scheme           = "EXTERNAL"
  port_name                       = "https"
  protocol                        = "HTTPS"
  timeout_sec                     = 15
  connection_draining_timeout_sec = 10
  health_checks                   = [google_compute_https_health_check.hc-pivii.0.id]
  security_policy                 = var.security_policy

  backend {
    group = element(google_compute_region_instance_group_manager.mig-pivii.*.instance_group,count.index)
  }

  backend {
    group = element(google_compute_region_instance_group_manager.mig-pivii1.*.instance_group,count.index)
  }
}


#############################################
## HA : Backend Service for OSI PI web OMF ##
#############################################
resource "google_compute_backend_service" "bk-womf" {
  count = var.architecture == "Non-HA" ? 0 : 1

  name                            = "bk-womf"
  project                         = var.project_id
  load_balancing_scheme           = "EXTERNAL"
  port_name                       = "https"
  protocol                        = "HTTPS"
  timeout_sec                     = 15
  connection_draining_timeout_sec = 10
  health_checks                   = [google_compute_health_check.hc-womf.0.id]
  security_policy                 = var.security_policy
  session_affinity                = "CLIENT_IP"
  # affinity_cookie_ttl_sec         = 900
  backend {
    group = element(google_compute_region_instance_group_manager.mig-womf.*.instance_group,count.index)
  }

  backend {
    group = element(google_compute_region_instance_group_manager.mig-womf1.*.instance_group,count.index)
  }
}


###################################################
## HA : URL Map for OSI PI vision/web/integrator ##
###################################################
resource "google_compute_url_map" "um-pivii" {
  count = var.architecture == "Non-HA" ? 0 : 1

  project         = var.project_id
  name            = "url-map-piviwb"
  default_service = google_compute_backend_service.bk-pivii[count.index].id


}


###########################################################
## HA : Google managed certificate for OSI PI vision/web ##
###########################################################
resource "google_compute_managed_ssl_certificate" "default" {

  count    = var.valid_domain == "No" ? 0 : 1
  provider = google-beta

  name     = "osi-cert"
  project  = var.project_id

  managed {
    domains = ["${var.ssl-dn-compute}"]
  }
}


###########################################
## HA : HTTP Proxy for OSI PI vision/web ##
###########################################
resource "google_compute_target_https_proxy" "proxy-pivii" {

  count    = var.valid_domain == "No" ? 0 : 1
  name             = "proxy-pivii"
  url_map          = google_compute_url_map.um-pivii[count.index].id
  ssl_certificates = [element(google_compute_managed_ssl_certificate.default.*.id,count.index)]

}


#############################################################
## HA : Creating private keys for self signed certificate ##
#############################################################
resource "tls_private_key" "self_private" {
  
  count    = var.valid_domain == "Yes" ? 0 : 1
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
 
}
resource "local_file" "self_key" {
  
  count    = var.valid_domain == "Yes" ? 0 : 1
  content  = tls_private_key.self_private[count.index].private_key_pem
  filename = "${path.module}/certs/self_key.pem"
}


############################################
## HA : Creating self signed certificate ##
############################################
resource "tls_self_signed_cert" "self_cert" {
  
  count    = var.valid_domain == "Yes" ? 0 : 1
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
  
  count    = var.valid_domain == "Yes" ? 0 : 1
  content  = tls_self_signed_cert.self_cert[count.index].cert_pem
  filename = "${path.module}/certs/self_cert.pem"
}


###############################################################################
## HA : Generating self signed certificate for OSI PI vision/web/integrator ##
###############################################################################

resource "google_compute_ssl_certificate" "default" {
  
  count    = var.valid_domain == "Yes" ? 0 : 1
  name     = "osi-cert"
  project  = var.project_id

  private_key = tls_private_key.self_private[count.index].private_key_pem
  certificate = tls_self_signed_cert.self_cert[count.index].cert_pem

  lifecycle {
    create_before_destroy = true
  }

}


##############################################################################
## HA : HTTPS Proxy for OSI PI vision/web/integrator with self signed cert ##
##############################################################################
resource "google_compute_target_https_proxy" "proxy-pivii2" {
  
  count    = var.valid_domain == "Yes" ? 0 : 1
  name             = "proxy-pivii2"
  url_map          = google_compute_url_map.um-pivii[count.index].id
  ssl_certificates = [element(google_compute_ssl_certificate.default.*.id,count.index)]

}


######################################################
## HA : External IP for External HTTPS Loadbalancer ##
######################################################
resource "google_compute_global_address" "default" {
  count = var.architecture == "Non-HA" ? 0 : 1
  name = "static-osipi"
}


##################################################################
## HA : Global forwarding rule for OSI PI vision/web/integrator ##
##################################################################
resource "google_compute_global_forwarding_rule" "fwd-pivii" {

  count    = var.valid_domain == "No" ? 0 : 1
  name                  = "fwd-pivii"
  project               = var.project_id
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL"
  port_range            = "443"
  target                = google_compute_target_https_proxy.proxy-pivii[count.index].id
  ip_address            = google_compute_global_address.default.0.address

}



#####################################################################################
## HA : Global forwarding rule for OSI PI vision/web/integrator for self signed cert
#####################################################################################
resource "google_compute_global_forwarding_rule" "fwd-pivii2" {
  
  count    = var.valid_domain == "Yes" ? 0 : 1
  name                  = "fwd-pivii2"
  project               = var.project_id
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL"
  port_range            = "443"
  target                = google_compute_target_https_proxy.proxy-pivii2[count.index].id
  ip_address            = google_compute_global_address.default.0.address

}









#########################################





###################################################
## HA : URL Map for OSI PI vision/web/integrator ##
###################################################
resource "google_compute_url_map" "um-womf" {
  count = var.architecture == "Non-HA" ? 0 : 1

  project         = var.project_id
  name            = "um-womf"
  default_service = google_compute_backend_service.bk-womf[count.index].id

}


###########################################################
## HA : Google managed certificate for OSI PI vision/web ##
###########################################################
resource "google_compute_managed_ssl_certificate" "default1" {

  count    = var.valid_domain == "No" ? 0 : 1
  provider = google-beta

  name     = "osi-cert1"
  project  = var.project_id

  managed {
    domains = ["${var.ssl-dn-compute}"]
  }
}


###########################################
## HA : HTTP Proxy for OSI PI vision/web ##
###########################################
resource "google_compute_target_https_proxy" "proxy-womf" {

  count    = var.valid_domain == "No" ? 0 : 1
  name             = "proxy-womf"
  url_map          = google_compute_url_map.um-womf[count.index].id
  ssl_certificates = [element(google_compute_managed_ssl_certificate.default1.*.id,count.index)]

}


#############################################################
## HA : Creating private keys for self signed certificate ##
#############################################################
resource "tls_private_key" "self_private1" {
  
  count    = var.valid_domain == "Yes" ? 0 : 1
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
 
}
resource "local_file" "self_key1" {
  
  count    = var.valid_domain == "Yes" ? 0 : 1
  content  = tls_private_key.self_private1[count.index].private_key_pem
  filename = "${path.module}/certs/self_key1.pem"
}

######################################################
## HA : External IP for External HTTPS Loadbalancer ##
######################################################
resource "google_compute_global_address" "default1" {
  count = var.architecture == "Non-HA" ? 0 : 1
  name = "static-osipi1"
}
############################################
## HA : Creating self signed certificate ##
############################################
resource "tls_self_signed_cert" "self_cert1" {
  
  count    = var.valid_domain == "Yes" ? 0 : 1
  key_algorithm     = "ECDSA"
  private_key_pem   = tls_private_key.self_private1[count.index].private_key_pem
 

  subject {
    common_name         = google_compute_global_address.default1.0.address
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
resource "local_file" "self_cert_file1" {
  
  count    = var.valid_domain == "Yes" ? 0 : 1
  content  = tls_self_signed_cert.self_cert1[count.index].cert_pem
  filename = "${path.module}/certs/self_cert1.pem"
}


###############################################################################
## HA : Generating self signed certificate for OSI PI vision/web/integrator ##
###############################################################################

resource "google_compute_ssl_certificate" "default1" {
  
  count    = var.valid_domain == "Yes" ? 0 : 1
  name     = "osi-cert2"
  project  = var.project_id

  private_key = tls_private_key.self_private1[count.index].private_key_pem
  certificate = tls_self_signed_cert.self_cert1[count.index].cert_pem

  lifecycle {
    create_before_destroy = true
  }

}


##############################################################################
## HA : HTTPS Proxy for OSI PI vision/web/integrator with self signed cert ##
##############################################################################
resource "google_compute_target_https_proxy" "proxy-womf1" {
  
  count    = var.valid_domain == "Yes" ? 0 : 1
  name             = "proxy-womf1"
  url_map          = google_compute_url_map.um-womf[count.index].id
  ssl_certificates = [element(google_compute_ssl_certificate.default1.*.id,count.index)]

}





##################################################################
## HA : Global forwarding rule for OSI PI vision/web/integrator ##
##################################################################
resource "google_compute_global_forwarding_rule" "fwd-omf" {

  count    = var.valid_domain == "No" ? 0 : 1
  name                  = "fwd-omf"
  project               = var.project_id
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL"
  port_range            = "443"
  target                = google_compute_target_https_proxy.proxy-womf[count.index].id
  ip_address            = google_compute_global_address.default1.0.address

}



#####################################################################################
## HA : Global forwarding rule for OSI PI vision/web/integrator for self signed cert
#####################################################################################
resource "google_compute_global_forwarding_rule" "fwd-omf1" {
  
  count    = var.valid_domain == "Yes" ? 0 : 1
  name                  = "fwd-omf1"
  project               = var.project_id
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL"
  port_range            = "443"
  target                = google_compute_target_https_proxy.proxy-womf1[count.index].id
  ip_address            = google_compute_global_address.default1.0.address

}


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

    count = var.architecture == "Non-HA" ? 3 : 8

    name                     = lookup(var.compute-multi-subnets,count.index)
    ip_cidr_range            = cidrsubnet(var.compute-multi-cidr,4,count.index + 2)
    network                  = google_compute_network.osi-vpc.id
    project                  = var.nw-projectid
    region                   = var.region_name
    private_ip_google_access = true
}


##############################
## Firewall Rules Non-HA ##
##############################
resource "google_compute_firewall" "osi-fw" {
    count = var.architecture == "HA" ? 0 : 1
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
    count = var.architecture == "HA" ? 0 : 1
    name          = "bastion-piweb"
    network       = google_compute_network.osi-vpc.name
    project       = var.nw-projectid
    source_tags = ["bastion"]
    priority      = "900"
    
    allow {
        protocol = "tcp"
        ports    = ["443","444","80"]
    }

    target_tags = ["osi-web"]


}

resource "google_compute_firewall" "osi-fw3" {
    count = var.architecture == "HA" ? 0 : 1
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
    count = var.architecture == "HA" ? 0 : 1
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
    count = var.architecture == "HA" ? 0 : 1
    name          = "lb-web"
    network       = google_compute_network.osi-vpc.name
    project       = var.nw-projectid
    source_ranges = ["35.191.0.0/16","130.211.0.0/22"]
    priority      = "900"
    
    allow {
        protocol = "tcp"
        #ports    = ["443"]
    }

    target_tags = ["health-check"]


}

resource "google_compute_firewall" "osi-fw6" {
    count = var.architecture == "HA" ? 0 : 1
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
    count = var.architecture == "HA" ? 0 : 1
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
    count = var.architecture == "HA" ? 0 : 1
    name          = "default-block"
    network       = google_compute_network.osi-vpc.name
    project       = var.nw-projectid
    source_ranges = ["0.0.0.0/0"]
    priority      = "65500"
    
    deny {
        protocol = "all"
    }
  
}

##############################
## Firewall Rules HA ##
##############################

resource "google_compute_firewall" "ha-osi-fw" {
    count = var.architecture == "Non-HA" ? 0 : 1
    name          = "allow-bastion-rdp-rdp"
    network       = google_compute_network.osi-vpc.name
    project       = var.nw-projectid
    source_tags = ["bastion"]
    priority      = "500"

    allow {
        protocol = "tcp"
        ports    = ["3389"]
    }

    target_tags = ["rdp"]
}

resource "google_compute_firewall" "ha-osi-fw2" {
    count = var.architecture == "Non-HA" ? 0 : 1
    name          = "allow-bastion-web-https"
    network       = google_compute_network.osi-vpc.name
    project       = var.nw-projectid
    source_tags = ["bastion"]
    priority      = "500"
    
    allow {
        protocol = "tcp"
        ports    = ["443","444"]
    }

    target_tags = ["osi-web"]
}

resource "google_compute_firewall" "ha-osi-fw3" {
    count = var.architecture == "Non-HA" ? 0 : 1
    name          = "allow-iap-bastion-rdp"
    network       = google_compute_network.osi-vpc.name
    project       = var.nw-projectid
    source_ranges = ["35.235.240.0/20"]
    priority      = "500"
    
    allow {
        protocol = "tcp"
        ports    = ["3389"]
    }

    target_tags = ["bastion"]


}

resource "google_compute_firewall" "ha-osi-fw4" {
    count = var.architecture == "Non-HA" ? 0 : 1
    name          = "allow-loadbalancer-osiweb-https"
    network       = google_compute_network.osi-vpc.name
    project       = var.nw-projectid
    source_ranges = ["35.191.0.0/16","130.211.0.0/22"]
    priority      = "500"
    
    allow {
        protocol = "tcp"
        ports    = ["443","444"]
    }

    target_tags = ["osi-web"]

}

resource "google_compute_firewall" "ha-osi-fw5" {
    count = var.architecture == "Non-HA" ? 0 : 1
    name          = "allow-loadbalancer-piaf-tcp"
    network       = google_compute_network.osi-vpc.name
    project       = var.nw-projectid
    source_ranges = ["35.191.0.0/16","130.211.0.0/22"]
    priority      = "500"
    
    allow {
        protocol = "tcp"
        ports    = ["5457"]
    }

    target_tags = ["pi-server"]


}

resource "google_compute_firewall" "ha-osi-fw6" {
    count = var.architecture == "Non-HA" ? 0 : 1
    name          = "allow-loadbalancer-pianno-tcp"
    network       = google_compute_network.osi-vpc.name
    project       = var.nw-projectid
    source_ranges = ["35.191.0.0/16","130.211.0.0/22"]
    priority      = "500"
    
    allow {
        protocol = "tcp"
        ports    = ["5463"]
    }

    target_tags = ["pianno-cluster"]


}

resource "google_compute_firewall" "ha-osi-fw7" {
    count = var.architecture == "Non-HA" ? 0 : 1
    name          = "allow-piclient-piserver-pianno"
    network       = google_compute_network.osi-vpc.name
    project       = var.nw-projectid
    source_tags = ["pi-client"]
    priority      = "500"
    
    allow {
        protocol = "tcp"
        ports    = ["5463","5468"]
    }

    target_tags = ["pi-anno"]


}

resource "google_compute_firewall" "ha-osi-fw8" {
    count = var.architecture == "Non-HA" ? 0 : 1
    name          = "allow-piclient-piserver-pianno-tmp"
    network       = google_compute_network.osi-vpc.name
    project       = var.nw-projectid
    source_tags = ["pi-client"]
    priority      = "500"
    
    allow {
        protocol = "tcp"
        ports    = ["5463","5468"]
    }

    target_tags = ["pianno-cluster"]

  
}

resource "google_compute_firewall" "ha-osi-fw9" {
    count = var.architecture == "Non-HA" ? 0 : 1
    name          = "allow-piclient-piserver-piservices"
    network       = google_compute_network.osi-vpc.name
    project       = var.nw-projectid
    source_tags = ["pi-client"]
    priority      = "500"
    
    allow {
        protocol = "tcp"
        ports    = ["5450","5457","5459"]
    }

    target_tags = ["pi-server"]

  
}

resource "google_compute_firewall" "ha-osi-fw10" {
    count = var.architecture == "Non-HA" ? 0 : 1
    name          = "allow-piserver-piserver-piservices"
    network       = google_compute_network.osi-vpc.name
    project       = var.nw-projectid
    source_tags = ["pi-server"]
    priority      = "500"
    
    allow {
        protocol = "tcp"
        ports    = ["5450","5457","5459","445","5985","135"]
    }

    allow {
    protocol = "icmp"
  }

    target_tags = ["pi-server"]
  
}

resource "google_compute_firewall" "ha-osi-fw11" {
    count = var.architecture == "Non-HA" ? 0 : 1
    name          = "allow-sqlclient-sqlservices-sqls"
    network       = google_compute_network.osi-vpc.name
    project       = var.nw-projectid
    source_tags = ["sql-client"]
    priority      = "500"
    
    allow {
        protocol = "tcp"
        ports    = ["1433"]
    }

    allow {
        protocol = "udp"
        ports    = ["1434"]
    }

    target_tags = ["sql-server"]

  
}

resource "google_compute_firewall" "ha-osi-fw12" {
    count = var.architecture == "Non-HA" ? 0 : 1
    name          = "allow-sqlserver-sqlcluster-mscluster"
    network       = google_compute_network.osi-vpc.name
    project       = var.nw-projectid
    source_ranges = ["10.0.2.0/24","10.0.3.0/24"]
    priority      = "500"
    
    allow {
        protocol = "tcp"
    }

    allow {
        protocol = "udp"
    }
    allow {
    protocol = "icmp"
  }

    target_tags = ["sql-cluster"]
  
}

resource "google_compute_firewall" "ha-osi-fw13" {
    count = var.architecture == "Non-HA" ? 0 : 1
    name          = "allow-pianno-piannocluster-mscluster"
    network       = google_compute_network.osi-vpc.name
    project       = var.nw-projectid
    source_ranges = ["10.0.6.0/24"]
    priority      = "500"
    
    allow {
        protocol = "tcp"
    }

    allow {
        protocol = "udp"
    }
  
}
resource "google_compute_firewall" "ha-osi-fw14" {
    count = var.architecture == "Non-HA" ? 0 : 1
    name          = "allow-pisvr-sql"
    network       = google_compute_network.osi-vpc.name
    project       = var.nw-projectid
    source_ranges = ["10.0.7.0/24"]
    priority      = "500"
    
    allow {
    protocol = "tcp"
    ports    = ["445","5985"]

  }

  
  allow {
    protocol = "icmp"
  }

    target_tags = ["sql-cluster"]


}

resource "google_compute_firewall" "ha-osi-fw15" {
    count = var.architecture == "Non-HA" ? 0 : 1
    name          = "allow-pianno-internal"
    network       = google_compute_network.osi-vpc.name
    project       = var.nw-projectid
    source_ranges = ["10.0.6.0/24"]
    priority      = "500"
    
    allow {
    protocol = "tcp"
    ports    = ["445","5985","135"]

  }

  

  allow {
    protocol = "icmp"
  }

    target_tags = ["pi-anno"]


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





##################  OLD


# ##################
# ## VPC Creation ##
# ##################
# resource "google_compute_network" "osi-vpc" {
#     auto_create_subnetworks = "false"
#     name                    = var.vpc_name
#     project                 = var.nw-projectid
#     routing_mode            = "REGIONAL"
# }


# #####################
# ## subnet creation ##
# #####################
# resource "google_compute_subnetwork" "osi-subnet" {

#     count = var.architecture == "Non-HA" ? 3 : 8

#     name                     = lookup(var.compute-multi-subnets,count.index)
#     ip_cidr_range            = cidrsubnet(var.compute-multi-cidr,4,count.index + 2)
#     network                  = google_compute_network.osi-vpc.id
#     project                  = var.nw-projectid
#     region                   = var.region_name
#     private_ip_google_access = true
# }


# ####################
# ## Firewall Rules ##
# ####################
# resource "google_compute_firewall" "osi-fw" {
#   name          = "pi-internal"
#   network       = google_compute_network.osi-vpc.name
#   project       = var.nw-projectid
#   source_ranges = ["${var.compute-multi-cidr}"]
#   priority      = "1000"

#   allow {
#     protocol = "tcp"
#     ports    = ["5450","1433","5457","5463","5468","5985","3389","5022","80","8080","443","3343","444","445","135","3260","49152-65535"]
#   }

#   allow {
#     protocol = "udp"
#     ports    = ["3343","445","135","138"]
#   }

#   allow {
#     protocol = "icmp"
#   }

#   target_tags = ["osi-internal"]
# }

# resource "google_compute_firewall" "osi-fw2" {
#   name          = "bastion-piweb"
#   network       = google_compute_network.osi-vpc.name
#   project       = var.nw-projectid
#   source_tags = ["bastion"]
#   priority      = "900"
  
#   allow {
#     protocol = "tcp"
#     ports    = ["443","444","80"]
#   }

#   target_tags = ["osi-web"]


# }

# resource "google_compute_firewall" "osi-fw3" {
#   name          = "bastion-rdp"
#   network       = google_compute_network.osi-vpc.name
#   project       = var.nw-projectid
#   source_tags = ["bastion"]
#   priority      = "900"
  
#   allow {
#     protocol = "tcp"
#     ports    = ["3389"]
#   }

#   target_tags = ["rdp"]


# }

# resource "google_compute_firewall" "osi-fw4" {
#   name          = "iap-compute"
#   network       = google_compute_network.osi-vpc.name
#   project       = var.nw-projectid
#   source_ranges = ["35.235.240.0/20"]
#   priority      = "900"
  
#   allow {
#     protocol = "tcp"
#     ports    = ["3389"]
#   }

#   target_tags = ["iap"]


# }

# resource "google_compute_firewall" "osi-fw5" {
#   name          = "lb-web"
#   network       = google_compute_network.osi-vpc.name
#   project       = var.nw-projectid
#   source_ranges = ["35.191.0.0/16","130.211.0.0/22"]
#   priority      = "900"
  
#   allow {
#     protocol = "tcp"
#     #ports    = ["443"]
#   }

#   target_tags = ["health-check"]


# }

# resource "google_compute_firewall" "osi-fw6" {
#   name          = "piclient-piserver"
#   network       = google_compute_network.osi-vpc.name
#   project       = var.nw-projectid
#   source_tags = ["pi-client"]
#   priority      = "900"
  
#   allow {
#     protocol = "tcp"
#     ports    = ["5450", "5457"]
#   }

#   target_tags = ["pi-server"]


# }

# resource "google_compute_firewall" "osi-fw7" {
#   name          = "sqlclient-sqlserver"
#   network       = google_compute_network.osi-vpc.name
#   project       = var.nw-projectid
#   source_tags = ["sql-client"]
#   priority      = "900"
  
#   allow {
#     protocol = "tcp"
#     ports    = ["1433"]
#   }

#   target_tags = ["sql-server"]


# }

# resource "google_compute_firewall" "osi-fw8" {
#   name          = "default-block"
#   network       = google_compute_network.osi-vpc.name
#   project       = var.nw-projectid
#   source_ranges = ["0.0.0.0/0"]
#   priority      = "65500"
  
#   deny {
#     protocol = "all"
#   }
  
# }

# resource "google_compute_firewall" "osi-fw9" {
#   count = var.architecture == "Non-HA" ? 0 : 1
#   name          = "pi-iscsi-fw"
#   network       = google_compute_network.osi-vpc.name
#   project       = var.nw-projectid
#   source_ranges = ["10.0.0.0/20"]
#   priority      = "1000"

#   allow {
#     protocol = "all"
#   }
#   target_tags = ["iscsi"]
# }


# #####################
# ## Output VPC Name ##
# #####################
# output "osi-vpc-out"{
#   value       = google_compute_network.osi-vpc.id
#   description = "VPC-ID for OSI_PI"
# }

# output "osi-vpc-name"{
#   value = google_compute_network.osi-vpc.name
# }


# #####################
# ## Output subnet Names ##
# #####################
# output "osi-subnet-out"{
#   value       = google_compute_subnetwork.osi-subnet.*.name
#   description = "Subnet name for OSI_PI"
# }

variable "project_id" {
  default = "null"
}

variable "architecture" {
  default = "null"
}

variable "region" {
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

variable "template-name" {
  type    = map(string)
  default = {
    0 = "it-pivision"
    1 = "it-piweb"
  }
}

variable "mig-name" {
  type    = map(string)
  default = {
    0 = "mig-pivision"
    1 = "mig-piweb"
  }
}

variable "bk-name" {
  type    = map(string)
  default = {
    0 = "bk-pivision"
    1 = "bk-piweb"
  }
}

variable "compute-region" {
  default = "null"
}

variable "zones" {
  
  type    = list(string)
}

variable "ssl-dn-compute" {
  default = "null"
}

variable "valid_domain" {
  default = "null"
}




#################
# Stateful disks 1
#################
variable "stateful_disks" {
  type = list(string)
  description = "(optional) describe your variable"
   default =  ["disk-daaf-1"]
  }
#################
# Rolling Update
#################

variable "update_policy" {
  description = "The rolling update policy. https://www.terraform.io/docs/providers/google/r/compute_region_instance_group_manager.html#rolling_update_policy"
  type = list(object({
    max_surge_percent            = number
    instance_redistribution_type = string
    max_unavailable_fixed        = number
    replacement_method           = string
    min_ready_sec                = number
    minimal_action               = string
    type                         = string
  }))
  default = [{
    type                         = "PROACTIVE"
    instance_redistribution_type = "NONE"
    minimal_action               = "RESTART"
    max_surge_percent            = 0
    max_unavailable_fixed        = 2
    min_ready_sec                = 50
    replacement_method           = "RECREATE"

  }]
}

#################
# Stateful disks 2
#################
variable "stateful_disks1" {
  type = list(string)
  description = "(optional) describe your variable"
   default =  ["disk-daaf-4"]
  }
#################
# Rolling Update
#################

variable "update_policy1" {
  description = "The rolling update policy. https://www.terraform.io/docs/providers/google/r/compute_region_instance_group_manager.html#rolling_update_policy"
  type = list(object({
    max_surge_percent            = number
    instance_redistribution_type = string
    max_unavailable_fixed        = number
    replacement_method           = string
    min_ready_sec                = number
    minimal_action               = string
    type                         = string
  }))
  default = [{
    type                         = "PROACTIVE"
    instance_redistribution_type = "NONE"
    minimal_action               = "RESTART"
    max_surge_percent            = 0
    max_unavailable_fixed        = 2
    min_ready_sec                = 50
    replacement_method           = "RECREATE"

  }]
}

#################
# Stateful disks 3
#################
variable "stateful_disks2" {
  type = list(string)
  description = "(optional) describe your variable"
   default =  ["disk-daaf-2"]
  }
#################
# Rolling Update
#################

variable "update_policy2" {
  description = "The rolling update policy. https://www.terraform.io/docs/providers/google/r/compute_region_instance_group_manager.html#rolling_update_policy"
  type = list(object({
    max_surge_percent            = number
    instance_redistribution_type = string
    max_unavailable_fixed        = number
    replacement_method           = string
    min_ready_sec                = number
    minimal_action               = string
    type                         = string
  }))
  default = [{
    type                         = "PROACTIVE"
    instance_redistribution_type = "NONE"
    minimal_action               = "RESTART"
    max_surge_percent            = 0
    max_unavailable_fixed        = 2
    min_ready_sec                = 50
    replacement_method           = "RECREATE"

  }]
}

################
# Stateful disks 4
################
variable "stateful_disks3" {
  type = list(string)
  description = "(optional) describe your variable"
   default =  ["disk-daaf-5"]
}

# Rolling Update
variable "update_policy3" {
  description = "The rolling update policy. https://www.terraform.io/docs/providers/google/r/compute_region_instance_group_manager.html#rolling_update_policy"
  type = list(object({
    max_surge_percent            = number
    instance_redistribution_type = string
    max_unavailable_fixed        = number
    replacement_method           = string
    min_ready_sec                = number
    minimal_action               = string
    type                         = string
  }))
  default = [{
    type                         = "PROACTIVE"
    instance_redistribution_type = "NONE"
    minimal_action               = "RESTART"
    max_surge_percent            = 0
    max_unavailable_fixed        = 2
    min_ready_sec                = 50
    replacement_method           = "RECREATE"

  }]
}

################
# Stateful disks 5
# ################
variable "stateful_disks4" {
  type = list(string)
  description = "(optional) describe your variable"
   default =  ["disk-pivii-1"]
}

# Rolling Update
variable "update_policy4" {
  description = "The rolling update policy. https://www.terraform.io/docs/providers/google/r/compute_region_instance_group_manager.html#rolling_update_policy"
  type = list(object({
    max_surge_percent            = number
    instance_redistribution_type = string
    max_unavailable_fixed        = number
    replacement_method           = string
    min_ready_sec                = number
    minimal_action               = string
    type                         = string
  }))
  default = [{
    type                         = "PROACTIVE"
    instance_redistribution_type = "NONE"
    minimal_action               = "RESTART"
    max_surge_percent            = 0
    max_unavailable_fixed        = 2
    min_ready_sec                = 50
    replacement_method           = "RECREATE"

  }]
}
# ################
# # Stateful disks 6
# ################
variable "stateful_disks5" {
  type = list(string)
  description = "(optional) describe your variable"
   default =  ["disk-pivii-2"]
}

# Rolling Update
variable "update_policy5" {
  description = "The rolling update policy. https://www.terraform.io/docs/providers/google/r/compute_region_instance_group_manager.html#rolling_update_policy"
  type = list(object({
    max_surge_percent            = number
    instance_redistribution_type = string
    max_unavailable_fixed        = number
    replacement_method           = string
    min_ready_sec                = number
    minimal_action               = string
    type                         = string
  }))
  default = [{
    type                         = "PROACTIVE"
    instance_redistribution_type = "NONE"
    minimal_action               = "RESTART"
    max_surge_percent            = 0
    max_unavailable_fixed        = 2
    min_ready_sec                = 50
    replacement_method           = "RECREATE"

  }]
}
################
# Stateful disks 7
################
variable "stateful_disks6" {
  type = list(string)
  description = "(optional) describe your variable"
    default =  ["disk-womf-1"]
}

# Rolling Update
variable "update_policy6" {
  description = "The rolling update policy. https://www.terraform.io/docs/providers/google/r/compute_region_instance_group_manager.html#rolling_update_policy"
  type = list(object({
    max_surge_percent            = number
    instance_redistribution_type = string
    max_unavailable_fixed        = number
    replacement_method           = string
    min_ready_sec                = number
    minimal_action               = string
    type                         = string
  }))
  default = [{
    type                         = "PROACTIVE"
    instance_redistribution_type = "NONE"
    minimal_action               = "RESTART"
    max_surge_percent            = 0
    max_unavailable_fixed        = 2
    min_ready_sec                = 50
    replacement_method           = "RECREATE"

  }]
}
# ################
# Stateful disks 8
################
variable "stateful_disks7" {
  type = list(string)
  description = "(optional) describe your variable"
   default =  ["disk-womf-2"]
}

# Rolling Update
variable "update_policy7" {
  description = "The rolling update policy. https://www.terraform.io/docs/providers/google/r/compute_region_instance_group_manager.html#rolling_update_policy"
  type = list(object({
    max_surge_percent            = number
    instance_redistribution_type = string
    max_unavailable_fixed        = number
    replacement_method           = string
    min_ready_sec                = number
    minimal_action               = string
    type                         = string
  }))
  default = [{
    type                         = "PROACTIVE"
    instance_redistribution_type = "NONE"
    minimal_action               = "RESTART"
    max_surge_percent            = 0
    max_unavailable_fixed        = 2
    min_ready_sec                = 50
    replacement_method           = "RECREATE"

  }]
}
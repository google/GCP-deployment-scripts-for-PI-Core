#########################
## Secret Manager - AD ##
#########################
resource "google_secret_manager_secret" "secret" {
  secret_id = var.secret_id
  project   = var.ad-projectid
  labels    = {
    label   = "osi-pi"
  }

  replication {
    automatic = true
  }
}


#######################
## Google Managed AD ##
#######################
resource "google_active_directory_domain" "ad-domain" {
  count = var.google-ad == "yes" ? 1 : 0

  domain_name         = "${var.ad-dn}"
  locations           = ["${var.ad-region}"]
  reserved_ip_range   = "${cidrsubnet(var.ad-cidr,4,0)}"
  authorized_networks = ["${var.vpc-out}"]
  project             = var.ad-projectid

  depends_on = [google_secret_manager_secret.secret]
}


###############################################
## Google AD password reset & store in secret##
###############################################
resource "null_resource" "google_active_directory1" {
  count = var.google-ad == "yes" ? 1 : 0
  provisioner "local-exec" {
    on_failure  = "continue"
    command     = "gcloud beta active-directory domains reset-admin-password ${var.ad-dn} --quiet --project=${var.ad-projectid} --format='value(password)' | gcloud secrets versions add ${var.secret_id} --project=${var.ad-projectid} --data-file=- "
    interpreter = ["PowerShell", "-Command"]
  }
  depends_on = [google_active_directory_domain.ad-domain]
}

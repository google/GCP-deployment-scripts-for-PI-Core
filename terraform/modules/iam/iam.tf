##############################
## Service Account Creation ##
##############################
resource "google_service_account" "osi-pi-sa" {
    account_id   = "osi-pi-sa"
    display_name = "osi-pi-sa"
    project      = var.project_id
}


########################
## Addind roles to SA ##
########################
resource "google_project_iam_member" "project" {
  count   = length(var.iam_role)

  project = var.project_id
  role    = "${element(var.iam_role,count.index)}"
  member  = "serviceAccount:${var.sa_email}"
}


#####################
## Output SA Email ##
#####################
output "sa-out"{
  value = google_service_account.osi-pi-sa.email
}

################
## Enable Api ##
################
resource "google_project_service" "project" {
  count   = length(var.gcp_service_list)
  project = var.project_id
  service = element(var.gcp_service_list,count.index)

  disable_dependent_services = true
}

output "enable_api_id" {
  value = google_project_service.project.*.id
}

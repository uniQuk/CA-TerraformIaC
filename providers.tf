terraform {
  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.0.1"
    }
  }
}

provider "azuread" {
  tenant_id = var.tenant_id
}

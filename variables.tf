variable "tenant_id" {
  description = "N7 Tenant ID"
  type        = string
}

variable "password_change_policies" {
  type = map(bool)
  default = {
    "Require password change for high-risk users.json" = true
  }
}

# variable "password_change_policies" {
#   type = map(bool)
#   default = {
#     "Require password change for high-risk users" = true
#   }
# }

variable "breakglass_group" {
  description = "Breakglass group"
  type        = string
}

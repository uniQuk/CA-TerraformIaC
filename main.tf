locals {
  # Define a local variable 'policy_files' that contains a list of all JSON files in the 'Policies' directory
  policy_files = fileset("${path.module}/Policies", "*.json")
}

data "local_file" "policy_files" {
  # Iterate over each policy file
  for_each = toset(local.policy_files)
  # Set the filename for each policy file
  filename = "${path.module}/Policies/${each.value}"
}

locals {
  # Decode the content of each policy file and store it in a local variable 'policies'
  policies = { for k, v in data.local_file.policy_files : k => jsondecode(v.content) }
}

resource "azuread_conditional_access_policy" "policies" {
  # Iterate over each policy in the 'policies' local variable
  for_each = local.policies

  # Set the display name and state of the policy
  display_name = each.value.displayName
  state        = "disabled"

  conditions {
    # Set the conditions for the policy
    client_app_types              = lookup(each.value.conditions, "clientAppTypes", [])
    sign_in_risk_levels           = lookup(each.value.conditions, "signInRiskLevels", [])
    user_risk_levels              = lookup(each.value.conditions, "userRiskLevels", [])
    service_principal_risk_levels = lookup(each.value.conditions, "servicePrincipalRiskLevels", [])

    applications {
      # Set the included and excluded applications and user actions
      included_applications = length(lookup(each.value.conditions.applications, "includeUserActions", [])) == 0 ? (
        contains(lookup(each.value.conditions.applications, "includeApplications", []), "All") ? ["All"] : lookup(each.value.conditions.applications, "includeApplications", [])
      ) : null
      excluded_applications = lookup(each.value.conditions.applications, "excludeApplications", [])
      included_user_actions = length(lookup(each.value.conditions.applications, "includeUserActions", [])) > 0 ? lookup(each.value.conditions.applications, "includeUserActions", []) : null
    }

    dynamic "client_applications" {
      # Set the client applications if they exist
      for_each = try(length(lookup(each.value.conditions, "clientApplications", [])) > 0 ? [1] : [], [])
      content {
        included_service_principals = lookup(each.value.conditions.clientApplications, "includeServicePrincipals", [])
        excluded_service_principals = lookup(each.value.conditions.clientApplications, "excludeServicePrincipals", [])
      }
    }

    users {
      # Set the included and excluded users, groups, and roles
      included_users  = lookup(each.value.conditions.users, "includeUsers", [])
      excluded_users  = lookup(each.value.conditions.users, "excludeUsers", [])
      included_groups = lookup(each.value.conditions.users, "includeGroups", [])
      excluded_groups = lookup(each.value.conditions.users, "excludeGroups", [])
      included_roles  = lookup(each.value.conditions.users, "includeRoles", [])
      excluded_roles  = lookup(each.value.conditions.users, "excludeRoles", [])
    }

    dynamic "locations" {
      # Set the locations if they exist
      for_each = each.value.conditions.locations != null ? [each.value.conditions.locations] : []
      content {
        included_locations = lookup(each.value.conditions.locations, "includeLocations", [])
        excluded_locations = lookup(each.value.conditions.locations, "excludeLocations", [])
      }
    }

    dynamic "platforms" {
      # Set the platforms if they exist
      for_each = each.value.conditions.platforms != null ? [each.value.conditions.platforms] : []
      content {
        included_platforms = lookup(platforms.value, "includePlatforms", ["all"])
        excluded_platforms = lookup(platforms.value, "excludePlatforms", [])
      }
    }
  } // end conditions

  dynamic "grant_controls" {
    # Set the grant controls if they exist
    for_each = each.value.grantControls != null ? [each.value.grantControls] : []
    content {
      operator                          = lookup(grant_controls.value, "operator", "OR")
      built_in_controls                 = lookup(grant_controls.value, "builtInControls", [])
      custom_authentication_factors     = lookup(grant_controls.value, "customAuthenticationFactors", [])
      terms_of_use                      = lookup(grant_controls.value, "termsOfUse", [])
      authentication_strength_policy_id = try(format("/policies/authenticationStrengthPolicies/%s", grant_controls.value.authenticationStrength.id), null)
    }
  }

  dynamic "session_controls" {
    # Set the session controls if they exist
    for_each = each.value.sessionControls != null ? [each.value.sessionControls] : []
    content {
      application_enforced_restrictions_enabled = (
        each.value.grantControls != null &&
        try(contains(each.value.grantControls.builtInControls, "passwordChange"), false)
      ) ? null : try(session_controls.value.applicationEnforcedRestrictions.isEnabled, false)

      cloud_app_security_policy = try(session_controls.value.cloudAppSecurity, null)

      disable_resilience_defaults = (
        each.value.grantControls != null &&
        try(contains(each.value.grantControls.builtInControls, "passwordChange"), false)
      ) ? null : try(session_controls.value.disableResilienceDefaults, false)

      persistent_browser_mode = try(
        session_controls.value.persistentBrowser != null && session_controls.value.persistentBrowser.isEnabled ? lookup(session_controls.value.persistentBrowser, "mode", null) : null,
        null
      )

      sign_in_frequency = (
        each.value.grantControls != null &&
        try(contains(each.value.grantControls.builtInControls, "passwordChange"), false)
      ) ? 0 : coalesce(try(session_controls.value.signInFrequency.value, null), 0)

      sign_in_frequency_period = (
        each.value.grantControls != null &&
        try(contains(each.value.grantControls.builtInControls, "passwordChange"), false)
      ) ? "hours" : coalesce(try(session_controls.value.signInFrequency.type, null), "hours")

      sign_in_frequency_authentication_type = (
        each.value.grantControls != null &&
        try(contains(each.value.grantControls.builtInControls, "passwordChange"), false)
      ) ? "primaryAndSecondaryAuthentication" : try(session_controls.value.signInFrequency.authenticationType, "primaryAndSecondaryAuthentication")

      sign_in_frequency_interval = (
        each.value.grantControls != null &&
        try(contains(each.value.grantControls.builtInControls, "passwordChange"), false)
      ) ? "everyTime" : try(session_controls.value.signInFrequency.frequencyInterval, "timeBased")
    }
  }
} // end resource

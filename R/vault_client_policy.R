##' Interact with vault's policies
##'
##' @template vault_client_policy
##'
##' @title Vault Policy Configuration
##' @name vault_client_policy
NULL


R6_vault_client_policy <- R6::R6Class(
  "vault_client_policy",
  inherit = vault_client_object,
  cloneable = FALSE,

  private = list(api_client = NULL),

  public = list(
    initialize = function(api_client) {
      super$initialize("Interact with policies")
      private$api_client <- api_client
    },

    delete = function(name) {
      assert_scalar_character(name)
      private$api_client$DELETE(paste0("/sys/policy/", name))
      invisible(NULL)
    },

    list = function() {
      dat <- private$api_client$GET("/sys/policy")
      list_to_character(dat$data$keys)
    },

    read = function(name) {
      assert_scalar_character(name)
      dat <- private$api_client$GET(paste0("/sys/policy/", name))
      dat$data$rules
    },

    write = function(name, rules) {
      assert_scalar_character(name)
      assert_scalar_character(rules)
      body <- list(rules = rules)
      private$api_client$PUT(paste0("/sys/policy/", name), body = body)
      invisible(NULL)
    }
  ))

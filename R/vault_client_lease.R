R6_vault_client_lease <- R6::R6Class(
  "vault_client_lease",

  private = list(api_client = NULL),

  public = list(
    initialize = function(api_client) {
      private$api_client <- api_client
    },

    format = function(brief = FALSE) {
      vault_client_format(self, brief, "lease",
                          "Interact with leases")
    }
  ))

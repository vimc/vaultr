R6_vault_client_policy <- R6::R6Class(
  "vault_client_policy",

  private = list(api_client = NULL),

  public = list(
    initialize = function(api_client) {
      private$api_client <- api_client
    },

    format = function(brief = FALSE) {
      vault_client_format(self, brief, "policy",
                          "Interact with policies")
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

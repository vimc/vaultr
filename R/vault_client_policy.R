##' Interact with vault's policies.  To get started, you may want to
##' read up on policies as described in the vault manual, here:
##' \url{https://www.vaultproject.io/docs/concepts/policies.html}
##'
##' @template vault_client_policy
##'
##' @title Vault Policy Configuration
##' @name vault_client_policy
##' @examples
##' server <- vaultr::vault_test_server(if_disabled = message)
##' if (!is.null(server)) {
##'   client <- server$client()
##'
##'   # The test server starts with only the policies "root" (do
##'   # everything) and "default" (do nothing).
##'   client$policy$list()
##'
##'   # Here let's make a policy that allows reading secrets from the
##'   # path /secret/develop/* but nothing else
##'   rules <- 'path "secret/develop/*" {policy = "read"}'
##'   client$policy$write("read-secret-develop", rules)
##'
##'   # Our new rule is listed and can be read
##'   client$policy$list()
##'   client$policy$read("read-secret-develop")
##'
##'   # For testing, let's create a secret under this path, and under
##'   # a different path:
##'   client$write("/secret/develop/password", list(value = "password"))
##'   client$write("/secret/production/password", list(value = "k2e89be@rdC#"))
##'
##'   # Create a token that can use this policy:
##'   token <- client$auth$token$create(policies = "read-secret-develop")
##'
##'   # Login to the vault using this token:
##'   alice <- vaultr::vault_client(addr = server$addr,
##'                                 login = "token", token = token)
##'
##'   # We can read the paths that we have been granted access to:
##'   alice$read("/secret/develop/password")
##'
##'   # We can't read secrets that are outside our path:
##'   try(alice$read("/secret/production/password"))
##'
##'   # And we can't write:
##'   try(alice$write("/secret/develop/password", list(value = "secret")))
##'
##'   # cleanup
##'   server$kill()
##' }
NULL


vault_client_policy <- R6::R6Class(
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

##' Administration commands for vault operators.  Very few of these
##' commands should be used without consulting the vault documentation
##' as they affect the administration of a vault server, but they are
##' included here for completeness.
##'
##' @template vault_client_operator
##'
##' @title Vault Administration
##' @name vault_client_operator
##' @examples
##'
##' server <- vaultr::vault_test_server(if_disabled = message)
##' if (!is.null(server)) {
##'   client <- server$client()
##'
##'   # Our test server is by default unsealed:
##'   client$status()$sealed
##'
##'   # We can seal the vault to prevent all access:
##'   client$operator$seal()
##'   client$status()$sealed
##'
##'   # And then unseal it again
##'   client$operator$unseal(server$keys)
##'   client$status()$sealed
##' }
NULL


vault_client_operator <- R6::R6Class(
  "vault_client_operator",
  inherit = vault_client_object,
  cloneable = FALSE,

  private = list(api_client = NULL),

  public = list(
    initialize = function(api_client) {
      super$initialize("Administration commands for vault operators")
      private$api_client <- api_client
    },

    key_status = function() {
      private$api_client$GET("/sys/key-status")
    },

    is_initialized = function() {
      d <- private$api_client$GET("/sys/init", allow_missing_token = TRUE)
      d$initialized
    },

    init = function(secret_shares, secret_threshold) {
      ## TODO: pgp not supported here
      assert_scalar_integer(secret_shares)
      assert_scalar_integer(secret_threshold)
      body <- list(secret_shares = secret_shares,
                   secret_threshold = secret_threshold)
      res <- private$api_client$PUT("/sys/init", body = body,
                                    allow_missing_token = TRUE)
      res$keys <- list_to_character(res$keys)
      res$keys_base64 <- list_to_character(res$keys_base64)
      res
    },

    leader_status = function() {
      private$api_client$GET("/sys/leader")
    },

    rekey_status = function() {
      private$api_client$GET("/sys/rekey/init")
    },

    rekey_start = function(secret_shares, secret_threshold) {
      assert_scalar_integer(secret_shares)
      assert_scalar_integer(secret_threshold)
      body <- list(secret_shares = secret_shares,
                   secret_threshold = secret_threshold,
                   backup = FALSE,
                   require_verification = FALSE)
      ## TODO: this is incorrect in the vault api docs
      ans <- private$api_client$PUT("/sys/rekey/init", body = body)
      ans
    },

    rekey_cancel = function() {
      private$api_client$DELETE("/sys/rekey/init")
      invisible(NULL)
    },

    rekey_submit = function(key, nonce) {
      assert_scalar_character(key)
      assert_scalar_character(nonce)
      body <- list(key = key, nonce = nonce)
      ans <- private$api_client$PUT("/sys/rekey/update", body = body)
      if (isTRUE(ans$complete)) {
        ans$keys <- list_to_character(ans$keys)
        ans$keys_base64 <- list_to_character(ans$keys_base64)
      }
      ans
    },

    rotate = function() {
      private$api_client$PUT("/sys/rotate")
      invisible(NULL)
    },

    seal = function() {
      private$api_client$PUT("/sys/seal")
      invisible(NULL)
    },

    seal_status = function() {
      private$api_client$GET("/sys/seal-status", allow_missing_token = TRUE)
    },

    unseal = function(key, reset = FALSE) {
      assert_scalar_character(key)
      assert_scalar_logical(reset)
      body <- list(key = key, reset = reset)
      private$api_client$PUT("/sys/unseal", body = body,
                             allow_missing_token = TRUE)
    }
  ))

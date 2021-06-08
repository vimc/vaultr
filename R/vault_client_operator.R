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

    ##' @description Return information about the current encryption
    ##'   key of Vault.
    key_status = function() {
      private$api_client$GET("/sys/key-status")
    },

    ##' @description Returns the initialization status of Vault
    is_initialized = function() {
      d <- private$api_client$GET("/sys/init", allow_missing_token = TRUE)
      d$initialized
    },

    ##' @description This endpoint initializes a new Vault. The Vault
    ##'   must not have been previously initialized.
    ##'
    ##' @param secret_shares Integer, specifying the number of shares
    ##'   to split the master key into
    ##'
    ##' @param secret_threshold Integer, specifying the number of
    ##'   shares required to reconstruct the master key. This must be
    ##'   less than or equal secret_shares
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

    ##' @description Check the high availability status and current
    ##'   leader of Vault
    leader_status = function() {
      private$api_client$GET("/sys/leader")
    },

    ##' @description Reads the configuration and progress of the
    ##'   current rekey attempt
    rekey_status = function() {
      private$api_client$GET("/sys/rekey/init")
    },

    ##' @description This method begins a new rekey attempt. Only a
    ##'   single rekey attempt can take place at a time, and changing
    ##'   the parameters of a rekey requires cancelling and starting a
    ##'   new rekey, which will also provide a new nonce.
    ##'
    ##' @param secret_shares Integer, specifying the number of shares
    ##'   to split the master key into
    ##'
    ##' @param secret_threshold Integer, specifying the number of
    ##'   shares required to reconstruct the master key. This must be
    ##'   less than or equal secret_shares
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

    ##' @description This method cancels any in-progress rekey. This
    ##'   clears the rekey settings as well as any progress made. This
    ##'   must be called to change the parameters of the rekey. Note
    ##'   verification is still a part of a rekey. If rekeying is
    ##'   cancelled during the verification flow, the current unseal
    ##'   keys remain valid.
    rekey_cancel = function() {
      private$api_client$DELETE("/sys/rekey/init")
      invisible(NULL)
    },

    ##' @description This method is used to enter a single master key
    ##'   share to progress the rekey of the Vault. If the threshold
    ##'   number of master key shares is reached, Vault will complete
    ##'   the rekey. Otherwise, this method must be called multiple
    ##'   times until that threshold is met. The rekey nonce operation
    ##'   must be provided with each call.
    ##'
    ##' @param key Specifies a single master share key (a string)
    ##'
    ##' @param nonce Specifies the nonce of the rekey operation (a
    ##'   string)
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

    ##' @description This method triggers a rotation of the backend
    ##'   encryption key. This is the key that is used to encrypt data
    ##'   written to the storage backend, and is not provided to
    ##'   operators. This operation is done online. Future values are
    ##'   encrypted with the new key, while old values are decrypted
    ##'   with previous encryption keys.
    rotate = function() {
      private$api_client$PUT("/sys/rotate")
      invisible(NULL)
    },

    ##' @description Seal the vault, preventing any access to it.
    ##'   After the vault is sealed, it must be unsealed for further
    ##'   use.
    seal = function() {
      private$api_client$PUT("/sys/seal")
      invisible(NULL)
    },

    ##' @description Check the seal status of a Vault.  This method can
    ##'   be used even when the client is not authenticated with the
    ##'   vault (which will the case for a sealed vault).
    seal_status = function() {
      private$api_client$GET("/sys/seal-status", allow_missing_token = TRUE)
    },

    ##' @description Submit a portion of a key to unseal the vault.
    ##'   This method is typically called by multiple different
    ##'   operators to assemble the master key.
    ##'
    ##' @param key The master key share
    ##'
    ##' @param reset Logical, indicating if the unseal process should
    ##'   start be started again.
    unseal = function(key, reset = FALSE) {
      assert_scalar_character(key)
      assert_scalar_logical(reset)
      body <- list(key = key, reset = reset)
      private$api_client$PUT("/sys/unseal", body = body,
                             allow_missing_token = TRUE)
    }
  ))

##' @rdname server_manager
vault_server_instance <- R6::R6Class(
  "vault_server_instance",
  inherit = vault_client_object,
  cloneable = FALSE,

  private = list(
    process = NULL
  ),

  public = list(
    ##' @field port The vault port (read-only).
    port = NULL,

    ##' @field addr The vault address; this is suitable for using with
    ##'   [vaultr::vault_client] (read-only).
    addr = NULL,

    ##' @field token The vault root token, from when the testing vault
    ##'   server was created.  If the vault is rekeyed this will no
    ##'   longer be accurate (read-only).
    token = NULL,

    ##' @field keys Key shares from when the vault was initialised
    ##'   (read-only).
    keys = NULL,

    ## @field cacert Path to the https certificate, if running in
    ##   https mode (read-only).
    cacert = NULL,

    initialize = function(bin, port, https, init) {
      super$initialize("Vault server instance")
      assert_scalar_integer(port)
      self$port <- port

      bin <- normalizePath(bin, mustWork = TRUE)
      if (https) {
        assert_scalar_logical(init)
        dat <- vault_server_start_https(bin, self$port, init)
      } else {
        dat <- vault_server_start_dev(bin, self$port)
      }

      private$process <- dat$process

      self$addr <- dat$addr
      self$token <- dat$token
      self$cacert <- dat$cacert
      self$keys <- dat$keys

      for (v in c("addr", "port", "token", "keys", "cacert")) {
        lockBinding(v, self)
      }
    },

    ## @description Return the server version, as a [numeric_version]
    ##   object.
    version = function() {
      self$client(FALSE)$api()$server_version()
    },

    ## @description Create a new client that can use this server.  The
    ##   client will be a [vaultr::vault_client] object.
    ##
    ## @param login Logical, indicating if the client should login to
    ##   the server (default is `TRUE`).
    ##
    ## @param quiet Logical, indicating if informational messages
    ##   should be suppressed.  Default is `TRUE`, in contrast with
    ##   most other methods.
    client = function(login = TRUE, quiet = TRUE) {
      vault_client(if (login) "token" else FALSE, token = self$token,
                   quiet = quiet, addr = self$addr, tls_config = self$cacert,
                   use_cache = FALSE)
    },

    finalize = function() {
      self$kill()
    },

    ## @description Return a named character vector of environment
    ##   variables that can be used to communicate with this vault
    ##   server (`VAULT_ADDR`, `VAULT_TOKEN`, etc).
    env = function() {
      c(VAULT_ADDR = self$addr,
        VAULT_TOKEN = self$token %||% NA_character_,
        VAULT_CACERT = self$cacert %||% NA_character_,
        VAULTR_AUTH_METHOD = "token")
    },

    ## @description Export the variables returned by the `$env()`
    ##   method to the environment.  This makes them available to
    ##   child processes.
    export = function() {
      env <- self$env()
      i <- is.na(env)
      do.call("Sys.setenv", as.list(env[!i]))
      if (any(i)) {
        Sys.unsetenv(names(env[i]))
      }
    },

    ## @description Clear any session-cached token for this server.
    ##   This is intended for testing new authentication backends.
    clear_cached_token = function() {
      vault_env$cache$delete(self)
    },

    ## @description Kill the server.
    kill = function() {
      if (!is.null(private$process)) {
        private$process$kill()
        private$process <- NULL
      }
    }
  ))

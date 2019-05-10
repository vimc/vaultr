vault_server_instance <- R6::R6Class(
  "vault_server_instance",
  inherit = vault_client_object,
  cloneable = FALSE,

  private = list(
    process = NULL
  ),

  public = list(
    port = NULL,
    addr = NULL,
    token = NULL,
    keys = NULL,
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

    version = function() {
      self$client(FALSE)$api()$server_version()
    },

    client = function(login = TRUE, quiet = TRUE) {
      vault_client(if (login) "token" else FALSE, token = self$token,
                   quiet = quiet, addr = self$addr, tls_config = self$cacert,
                   use_cache = FALSE)
    },

    finalize = function() {
      self$kill()
    },

    env = function() {
      c(VAULT_ADDR = self$addr,
        VAULT_TOKEN = self$token %||% NA_character_,
        VAULT_CACERT = self$cacert %||% NA_character_,
        VAULTR_AUTH_METHOD = "token")
    },

    export = function() {
      env <- self$env()
      i <- is.na(env)
      do.call("Sys.setenv", as.list(env[!i]))
      if (any(i)) {
        Sys.unsetenv(names(env[i]))
      }
    },

    clear_cached_token = function() {
      vault_env$cache$delete(self)
    },

    kill = function() {
      if (!is.null(private$process)) {
        private$process$kill()
        private$process <- NULL
      }
    }
  ))

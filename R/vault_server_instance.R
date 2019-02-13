##' Control a vault server instance in a testing environnment.
##' Objects of this type are returned by
##' \code{\link{vault_test_server}}.
##'
##' The server will stay alive for as long as the R process is alive
##' \emph{or} until the \code{vault_server_instance} object goes out
##' of scope and is garbage collected.  Calling \code{$kill()} will
##' explicitly stop the server, but this is not strictly needed.
##'
##' @template vault_server_instance
##'
##' @title Vault Server Instance
##' @name vault_server_instance
NULL


R6_vault_server_instance <- R6::R6Class(
  "vault_server_instance",

  public = list(
    port = NULL,

    process = NULL,
    addr = NULL,
    cacert = NULL,

    token = NULL,
    keys = NULL,

    initialize = function(bin, port, https, init) {
      assert_scalar_integer(port)
      self$port <- port

      bin <- normalizePath(bin, mustWork = TRUE)
      if (https) {
        assert_scalar_logical(init)
        dat <- vault_server_start_https(bin, self$port, init)
      } else {
        dat <- vault_server_start_dev(bin, self$port)
      }

      for (i in names(dat)) {
        self[[i]] <- dat[[i]]
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
      if (!is.null(self$process)) {
        self$process$kill()
        self$process <- NULL
      }
    }
  ))

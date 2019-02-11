##' Make a vault client.  This must be done before accessing the
##' vault.  The deafults for arguments are controlled by environment
##' variables (see Details) and values provided as arguments override
##' these defaults.
##'
##' @title Make a vault client
##'
##' @param login Login method.  Specify a string to be passed along as
##'   the \code{method} argument to \code{$login}.  The default
##'   \code{FALSE} means not to login.  \code{TRUE} means to login
##'   using a default method specified by the environment variable
##'   \code{VAULTR_AUTH_METHOD} - if that variable is not set, an
##'   error is thrown.  The value of \code{NULL} is the same as
##'   \code{TRUE} but does not throw an error if
##'   \code{VAULTR_AUTH_METHOD} is not set.  Supported methods are
##'   \code{token}, \code{github} and \code{userpass}.
##'
##' @param ... Additional arguments passed along to the authentication
##'   method indicated by \code{login}, if used.
##'
##' @param addr The value address \emph{including protocol and port},
##'   e.g., \code{https://vault.example.com:8200}.  If not given, the
##'   default is the environment variable \code{VAULT_ADDR}, which is
##'   the same as used by vault's command line client.
##'
##' @param tls_config TLS (https) configuration.  For most uses this
##'   can be left blank.  However, if your vault server uses a
##'   self-signed certificate you will need to provide this.  Defaults
##'   to the environment variable \code{VAULT_CAPATH}, which is the
##'   same as vault's command line client.
##'
##' @template vault_client
##' @export
##' @author Rich FitzJohn
vault_client <- function(login = FALSE, ..., addr = NULL, tls_config = NULL) {
  client <- R6_vault_client$new(addr, tls_config)
  method <- vault_client_login_method(login)
  if (!is.null(method)) {
    client$login(..., method = method)
  }
  client
}


R6_vault_client <- R6::R6Class(
  "vault_client",

  cloneable = FALSE,

  private = list(
    api_client = NULL),

  public = list(
    auth = NULL,
    audit = NULL,
    kv1 = NULL,
    kv2 = NULL,
    lease = NULL,
    operator = NULL,
    policy = NULL,
    secrets = NULL,
    token = NULL,
    tools = NULL,

    initialize = function(addr, tls_config) {
      api_client <- vault_api_client$new(addr, tls_config)

      private$api_client <- api_client

      self$auth <- R6_vault_client_auth$new(api_client)
      self$audit <- R6_vault_client_audit$new(api_client)
      self$kv1 <- R6_vault_client_kv1$new(api_client, NULL)
      self$kv2 <- R6_vault_client_kv2$new(api_client, "secret")
      self$lease <- R6_vault_client_lease$new(api_client)
      self$operator <- R6_vault_client_operator$new(api_client)
      self$policy <- R6_vault_client_policy$new(api_client)
      self$secrets <- R6_vault_client_secrets$new(api_client)
      self$token <- R6_vault_client_token$new(api_client)
      self$tools <- R6_vault_client_tools$new(api_client)
    },

    format = function(brief = FALSE) {
      vault_client_format(self, brief, "base",
                          "core methods for interacting with vault")
    },

    api = function() {
      private$api_client
    },

    ## Root object kv1 methods
    read = function(path, field = NULL, metadata = FALSE) {
      self$kv1$read(path, field, metadata)
    },

    write = function(path, data) {
      self$kv1$write(path, data)
    },

    delete = function(path) {
      self$kv1$delete(path)
    },

    ## NOTE: no recursive list here
    list = function(path, full_names = FALSE) {
      self$kv1$list(path, full_names)
    },

    login = function(..., method = "token", mount = NULL,
                     renew = FALSE, quiet = FALSE,
                     token_only = FALSE, use_cache = TRUE) {
      do_auth <-
        assert_scalar_logical(renew) ||
        assert_scalar_logical(token_only) ||
        !private$api_client$is_authenticated()
      if (!do_auth) {
        return(NULL)
      }

      auth <- self$auth[[method]]
      if (!inherits(auth, "R6")) {
        stop(sprintf(
          "Unknown login method '%s' - must be one of %s",
          method, paste(squote(self$auth$backends()), collapse = ", ")),
          call. = FALSE)
      }
      if (!is.null(mount)) {
        if (method == "token") {
          stop("method 'token' does not accept a custom mount")
        }
        auth <- auth$custom_mount(mount)
      }

      ## TODO: Feedback usage information here on failure?
      assert_scalar_character(method)
      assert_named(list(...), "...")
      if (method == "token") {
        token <- auth$login(..., quiet = quiet)
      } else {
        token <- vault_env$cache$get(private$api_client,
                                     use_cache && !token_only)
        if (is.null(token)) {
          data <- auth$login(...)
          if (!quiet) {
            message(pretty_lease(data$lease_duration))
          }
          token <- data$client_token
          if (!token_only) {
            vault_env$cache$set(private$api_client, token, use_cache)
          }
        }
      }

      if (!token_only) {
        private$api_client$set_token(token)
      }

      invisible(token)
    },

    status = function() {
      self$operator$seal_status()
    }
  ))


vault_client_login_method <- function(login) {
  if (isFALSE(login)) {
    return(NULL)
  }
  if (is.null(login) || isTRUE(login)) {
    required <- isTRUE(login)
    login <- Sys_getenv("VAULTR_AUTH_METHOD", NULL)
    if (is.null(login)) {
      if (required) {
        stop("Default login method not set in 'VAULTR_AUTH_METHOD'",
             call. = FALSE)
      } else {
        return(NULL)
      }
    }
  }
  assert_scalar_character(login)
  login
}

##' Low-level API client.  This can be used to directly communicate
##' with the vault server.  This object will primarily be useful for
##' debugging, testing or developing new vault methods, but is
##' nonetheless described here.
##'
##' @template vault_api_client
##'
##' @title Vault Low-Level Client
##' @name vault_api_client
NULL


R6_vault_api_client <- R6::R6Class(
  "vault_api_client",

  public = list(
    addr = NULL,
    base_url = NULL,
    tls_config = NULL,
    token = NULL,
    version = NULL,

    initialize = function(addr = NULL, tls_config = NULL) {
      self$addr <- vault_addr(addr)
      self$base_url <- vault_base_url(self$addr, "/v1")
      self$tls_config <- vault_tls_config(tls_config)
    },

    request = function(verb, path, ..., token = self$token) {
      vault_request(verb, self$base_url, self$tls_config, token,
                    path, ...)
    },

    is_authenticated = function() {
      !is.null(self$token)
    },

    set_token = function(token, verify = FALSE, quiet = FALSE) {
      if (verify) {
        dat <- self$verify_token(token, quiet)
        if (!dat$success) {
          stop("Token validation failed with error: ", dat$error)
        }
      }
      self$token <- token
    },

    verify_token = function(token, quiet = TRUE) {
      if (!quiet) {
        message("Verifying token")
      }
      res <- tryCatch(
        vault_request(httr::POST, self$base_url, self$tls_config, token,
                      "/sys/capabilities-self",
                      body = list(path = "/sys")),
        error = identity)
      success <- !inherits(res, "error")
      list(success = success,
           error = if (!success) res,
           token = if (success) token)
    },

    server_version = function(refresh = FALSE) {
      if (is.null(self$version) || refresh) {
        self$version <- numeric_version(
          self$GET("/sys/seal-status", allow_missing_token = TRUE)$version)
      }
      self$version
    },

    GET = function(path, ...) {
      self$request(httr::GET, path, ...)
    },

    LIST = function(path, ...) {
      self$request(httr_LIST, path, ...)
    },

    POST = function(path, ...) {
      self$request(httr::POST, path, ...)
    },

    PUT = function(path, ...) {
      self$request(httr::PUT, path, ...)
    },

    DELETE = function(path, ...) {
      self$request(httr::DELETE, path, ...)
    }
  ))


vault_tls_config <- function(tls_config) {
  tls_config <- vault_arg(tls_config, "VAULT_CAPATH")
  if (is.null(tls_config)) {
    NULL
  } else if (identical(as.vector(tls_config), FALSE)) {
    httr::config(ssl_verifypeer = 0, ssl_verifyhost = 0)
  } else {
    assert_file_exists(tls_config)
    httr::config(cainfo = tls_config)
  }
}



vault_addr <- function(addr) {
  addr <- addr %||% Sys.getenv("VAULT_ADDR", "")
  assert_scalar_character(addr)
  if (!nzchar(addr)) {
    stop("vault address not found: perhaps set 'VAULT_ADDR'", call. = FALSE)
  }
  if (!grepl("^https?://.+", addr)) {
    stop("Expected an http or https url for vault addr")
  }
  addr
}


vault_base_url <- function(addr, api_prefix) {
  assert_scalar_character(api_prefix)
  paste0(addr, api_prefix)
}


httr_LIST <- function(...) {
  httr::VERB("LIST", ...)
}

##' Low-level API client.  This can be used to directly communicate
##' with the vault server.  This object will primarily be useful for
##' debugging, testing or developing new vault methods, but is
##' nonetheless described here.
##'
##' @title Vault Low-Level Client
##' @name vault_api_client
##'
##' @examples
##'
##' server <- vaultr::vault_test_server(if_disabled = message)
##' if (!is.null(server)) {
##'   # Ordinarily, we would use the "vault_client" object for
##'   # high-level access to the vault server
##'   client <- server$client()
##'   client$status()
##'
##'   # The api() method returns the "api client" object:
##'   api <- client$api()
##'   api
##'
##'   # This allows running arbitrary HTTP requests against the server:
##'   api$GET("/sys/seal-status")
##'
##'   # this is how vaultr is internally implemented so anything can
##'   # be done here, for example following vault's API documentation
##'   # https://www.vaultproject.io/api/secret/kv/kv-v1.html#sample-request-2
##'   api$POST("/secret/mysecret", body = list(key = "value"))
##'   api$GET("/secret/mysecret")
##'   api$DELETE("/secret/mysecret")
##'
##'   # cleanup
##'   server$kill()
##' }
vault_api_client <- R6::R6Class(
  "vault_api_client",
  inherit = vault_client_object,
  cloneable = FALSE,

  public = list(
    ##' @field addr The vault port
    addr = NULL,

    ##' @field base_url The base url (with protocol, hostname and api version)
    base_url = NULL,

    ##' @field tls_config Information used in TLS config, if used
    tls_config = NULL,

    ##' @field token The vault token, if authenticated
    token = NULL,

    ##' @field version The vault server version, once queried
    version = NULL,

    ##' @description Create a new api client
    ##'
    ##' @param addr Address of the vault server
    ##'
    ##' @param tls_config Optional TLS config
    initialize = function(addr = NULL, tls_config = NULL) {
      super$initialize("Low-level API client")
      self$addr <- vault_addr(addr)
      self$base_url <- vault_base_url(self$addr, "/v1")
      self$tls_config <- vault_tls_config(tls_config)
    },

    ##' @description Make a request to the api. Typically you should use
    ##' one of the higher-level wrappers, such as `$GET` or `$POST`.
    ##'
    ##' @param verb The HTTP verb to use, as a `httr` function (e.g.,
    ##'   pass `httr::GET` for a `GET` request).
    ##'
    ##' @param path The request path
    ##'
    ##' @param ... Additional arguments passed to the `httr` function
    ##'
    ##' @param token Optional token, overriding the client token
    request = function(verb, path, ..., token = self$token) {
      vault_request(verb, self$base_url, self$tls_config, token,
                    path, ...)
    },

    ##' @description Test if the vault client currently holds a vault token.
    ##'   This method does not verify the token - only test that is present.
    is_authenticated = function() {
      !is.null(self$token)
    },

    ##' @description Set a token within the client
    ##'
    ##' @param token String, with the new vault client token
    ##'
    ##' @param verify Logical, indicating if we should test that the token
    ##'   is valid. If `TRUE`, then we use `$verify_token()` to test the
    ##'   token before setting it and if it is not valid an error will be
    ##'   thrown and the token not set.
    ##'
    ##' @param quiet Logical, if `TRUE`, then informational messages will be
    ##'   suppressed.
    set_token = function(token, verify = FALSE, quiet = FALSE) {
      if (verify) {
        dat <- self$verify_token(token, quiet)
        if (!dat$success) {
          stop("Token validation failed with error: ", dat$error)
        }
      }
      self$token <- token
    },

    ##' @description Test that a token is valid with the vault.
    ##'   This will call vault's `/sys/capabilities-self` endpoint with the
    ##'   token provided and check the `/sys` path.
    ##'
    ##' @param token String, with the vault client token to test
    ##'
    ##' @param quiet Logical, if `TRUE`, then informational messages will be
    ##'   suppressed
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

    ##' @description Retrieve the vault server version.  This is by default
    ##'   cached within the client for a session.  Will return an R
    ##'   [numeric_version] object.
    ##'
    ##' @param refresh Logical, indicating if the server version information
    ##'   should be refreshed even if known.
    server_version = function(refresh = FALSE) {
      if (is.null(self$version) || refresh) {
        self$version <- numeric_version(
          self$GET("/sys/seal-status", allow_missing_token = TRUE)$version)
      }
      self$version
    },

    ##' @description Send a `GET` request to the vault server
    ##'
    ##' @param path The server path to use.  This is the "interesting"
    ##'   part of the path only, with the server base url and api version
    ##'   information added.
    ##'
    ##' @param ... Additional `httr`-compatible options.  These will be named
    ##'   parameters or `httr` "request" objects.
    GET = function(path, ...) {
      self$request(httr::GET, path, ...)
    },

    ##' @description Send a `LIST` request to the vault server
    ##'
    ##' @param path The server path to use.  This is the "interesting"
    ##'   part of the path only, with the server base url and api version
    ##'   information added.
    ##'
    ##' @param ... Additional `httr`-compatible options.  These will be named
    ##'   parameters or `httr` "request" objects.
    LIST = function(path, ...) {
      self$request(httr_LIST, path, ...)
    },

    ##' @description Send a `POST` request to the vault server
    ##'
    ##' @param path The server path to use.  This is the "interesting"
    ##'   part of the path only, with the server base url and api version
    ##'   information added.
    ##'
    ##' @param ... Additional `httr`-compatible options.  These will be named
    ##'   parameters or `httr` "request" objects.
    POST = function(path, ...) {
      self$request(httr::POST, path, ...)
    },

    ##' @description Send a `PUT` request to the vault server
    ##'
    ##' @param path The server path to use.  This is the "interesting"
    ##'   part of the path only, with the server base url and api version
    ##'   information added.
    ##'
    ##' @param ... Additional `httr`-compatible options.  These will be named
    ##'   parameters or `httr` "request" objects.
    PUT = function(path, ...) {
      self$request(httr::PUT, path, ...)
    },

    ##' @description Send a `DELETE` request to the vault server
    ##'
    ##' @param path The server path to use.  This is the "interesting"
    ##'   part of the path only, with the server base url and api version
    ##'   information added.
    ##'
    ##' @param ... Additional `httr`-compatible options.  These will be named
    ##'   parameters or `httr` "request" objects.
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


httr_LIST <- function(...) { # nolint
  httr::VERB("LIST", ...)
}

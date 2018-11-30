## This is the low level api client - most of the transport bits go here
vault_api_client <- R6::R6Class(
  "vault_api_client",

  public = list(
    base_url = NULL,
    tls_config = NULL,
    token = NULL,
    auth = NULL,

    initialize = function(addr = NULL, tls_config = NULL) {
      self$base_url <- vault_base_url(addr, "/v1")
      self$tls_config <- vault_tls_config(tls_config)
    },

    request = function(verb, path, ...) {
      vault_request(verb, self$base_url, self$tls_config, self$auth,
                    path, ...)
    },

    is_authenticated = function() {
      !is.null(self$token)
    },

    set_token = function(token, verify = FALSE) {
      self$token <- token
      self$auth <- httr::add_headers("X-Vault-Token" = token)
    },

    get_token = function() {
      self$token
    },

    clear_token = function() {
      self$token <- NULL
      self$auth <- NULL
    },

    verify_token = function(token) {
      auth <- httr::add_headers("X-Vault-Token" = token)
      res <- tryCatch(
        vault_request(httr::POST, self$base_url, self$tls_config, auth,
                      "/sys/capabilities-self",
                      body = list(path = "/sys"), encode = "json"),
        error = identity)
      success <- !inherits(res, "error")
      list(success = success,
           error = if (!success) success,
           auth = if (success) auth)
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


vault_base_url <- function(addr, api_prefix) {
  addr <- addr %||%
    getOption("vault.addr",
              Sys.getenv("VAULT_ADDR", NA_character_))
  assert_scalar_character(addr)
  if (!is.character(addr) || length(addr) != 1L) {
    stop("invalid input for vault addr")
  }
  if (is.na(addr)) {
    stop("vault address not found")
  }
  if (!grepl("^https://.+", addr)) {
    stop("Expected an https url for vault addr")
  }

  paste0(addr, api_prefix)
}


httr_LIST <- function(...) {
  httr::VERB("LIST", ...)
}

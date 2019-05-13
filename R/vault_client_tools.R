##' Interact with vault's cryptographic tools.  This provides support
##' for high-quality random numbers and cryptographic hashes.  This
##' functionality is also available through the transit secret engine.
##'
##' @template vault_client_tools
##'
##' @title Vault Tools
##' @name vault_client_tools
##' @examples
##' server <- vaultr::vault_test_server(if_disabled = message)
##' if (!is.null(server)) {
##'   client <- server$client()
##'
##'   # Random bytes in hex
##'   client$tools$random()
##'   # base64
##'   client$tools$random(format = "base64")
##'   # raw
##'   client$tools$random(10, format = "raw")
##'
##'   # Hash data:
##'   data <- charToRaw("hello vault")
##'   # will produce 55e702...92efd40c2a4
##'   client$tools$hash(data)
##'
##'   # sha2-512 hash:
##'   client$tools$hash(data, "sha2-512")
##'
##'   # cleanup
##'   server$kill()
##' }
NULL


vault_client_tools <- R6::R6Class(
  "vault_client_tools",
  inherit = vault_client_object,
  cloneable = FALSE,

  private = list(
    api_client = NULL,
    mount = NULL
  ),

  public = list(
    initialize = function(api_client) {
      private$api_client <- api_client
      super$initialize("General tools provided by vault")
    },

    random = function(bytes = 32, format = "hex") {
      body <- list(bytes = assert_scalar_integer(bytes),
                   format = assert_scalar_character(format))
      if (format == "raw") {
        body$format <- "base64"
      }
      res <- private$api_client$POST("/sys/tools/random", body = body)
      bytes <- res$data$random_bytes
      if (format == "raw") {
        decode64(bytes)
      } else {
        bytes
      }
    },

    hash = function(data, algorithm = NULL, format = "hex") {
      body <- list(input = raw_data_input(data),
                   algorithm = algorithm,
                   format = assert_scalar_character(format))
      private$api_client$POST("/sys/tools/hash", body = body)$data$sum
    }
  ))

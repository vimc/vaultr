##' Interact with vault's cryptographic tools.  This provides support
##' for high-quality random numbers and cryptographic hashes.  This
##' functionality is also available through the transit secret engine.
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
vault_client_tools <- R6::R6Class(
  "vault_client_tools",
  inherit = vault_client_object,
  cloneable = FALSE,

  private = list(
    api_client = NULL,
    mount = NULL
  ),

  public = list(
    ##' @description Create a `vault_client_tools` object. Not typically
    ##'   called by users.
    ##'
    ##' @param api_client A [vaultr::vault_api_client] object
    initialize = function(api_client) {
      private$api_client <- api_client
      super$initialize("General tools provided by vault")
    },

    ##' @description Generates high-quality random bytes of the
    ##'   specified length.  This is totally independent of R's random
    ##'   number stream and provides random numbers suitable for
    ##'   cryptographic purposes.
    ##'
    ##' @param bytes Number of bytes to generate (as an integer)
    ##'
    ##' @param format The output format to produce; must be one of
    ##'   `hex` (a single hex string such as `d1189e2f83b72ab6`),
    ##'   `base64` (a single base64 encoded string such as
    ##'   `8TDJekY0mYs=`) or `raw` (a raw vector of length `bytes`).
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

    ##' @description Generates a cryptographic hash of given data using
    ##'   the specified algorithm.
    ##'
    ##' @param data A raw vector of data to hash.  To generate a raw
    ##'   vector from an R object, one option is to use `unserialize(x,
    ##'   NULL)` but be aware that version information may be included.
    ##'   Alternatively, for a string, one might use `charToRaw`.
    ##'
    ##' @param algorithm A string indicating the hash algorithm to use.
    ##'   The exact set of supported algorithms may depend by vault
    ##'   server version, but as of version 1.0.0 vault supports
    ##'   `sha2-224`, `sha2-256`, `sha2-384` and `sha2-512`.  The
    ##'   default is `sha2-256`.
    ##'
    ##' @param format The format of the output - must be one of `hex`
    ##'    or `base64`.
    hash = function(data, algorithm = NULL, format = "hex") {
      body <- list(input = raw_data_input(data),
                   algorithm = algorithm,
                   format = assert_scalar_character(format))
      private$api_client$POST("/sys/tools/hash", body = body)$data$sum
    }
  ))

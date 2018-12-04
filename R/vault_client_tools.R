R6_vault_client_tools <- R6::R6Class(
  "vault_client_tools",

  private = list(
    api_client = NULL,
    mount = NULL
  ),

  public = list(
    initialize = function(api_client) {
      private$api_client <- api_client
    },

    format = function(brief = FALSE) {
      vault_client_format(self, brief, "tools",
                          "General tools provided by vault")
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
      if (!is.raw(data)) {
        ## TODO: should this support base64 data?
        stop("Expected raw data")
      }
      body <- list(input = encode64(data),
                   algorithm = algorithm,
                   format = assert_scalar_character(format))
      private$api_client$POST("/sys/tools/hash", body = body)$data$sum
    }
  ))

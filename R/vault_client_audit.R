##' Interact with vault's audit devices.  For more details, see
##' https://www.vaultproject.io/docs/audit/
##'
##' @title Vault Audit Devices
##' @name vault_client_audit
##'
##' @examples
##' server <- vaultr::vault_test_server(if_disabled = message)
##' if (!is.null(server)) {
##'   client <- server$client()
##'   # By default no audit engines are enabled with the testing server
##'   client$audit$list()
##'
##'   # Create a file-based audit device on a temporary file:
##'   path <- tempfile()
##'   client$audit$enable("file", options = list(file_path = path))
##'   client$audit$list()
##'
##'   # Generate some activity on the server:
##'   client$write("/secret/mysecret", list(key = "value"))
##'
##'   # The audit logs contain details about the activity - see the
##'   # vault documentation for details in interpreting this
##'   readLines(path)
##'
##'   # cleanup
##'   server$kill()
##'   unlink(path)
##' }
vault_client_audit <- R6::R6Class(
  "vault_client_audit",
  inherit = vault_client_object,
  cloneable = FALSE,

  private = list(api_client = NULL),

  public = list(
    ##' @description Create an audit object
    ##'
    ##' @param api_client a [vaultr::vault_api_client] object
    initialize = function(api_client) {
      super$initialize("Interact with vault's audit devices")
      private$api_client <- api_client
    },

    ##' @description List active audit devices.  Returns a [data.frame]
    ##'   of names, paths and descriptions of active audit devices.
    list = function() {
      dat <- private$api_client$GET("/sys/audit")
      cols <- c("path", "type", "description")
      ret <- lapply(cols, function(v)
        vcapply(dat$data, "[[", v, USE.NAMES = FALSE))
      names(ret) <- cols
      as.data.frame(ret, stringsAsFactors = FALSE, check.names = FALSE)
    },

    ##' @description This endpoint enables a new audit device at the
    ##'   supplied path.
    ##'
    ##' @param type Name of the audit device to enable
    ##'
    ##' @param description Human readable description for this audit device
    ##'
    ##' @param options Options to configure the device with.  These vary
    ##'   by device. This must be a named list of strings.
    ##'
    ##' @param path Path to mount the audit device.  By default, `type` is used
    ##'   as the path.
    enable = function(type, description = NULL, options = NULL, path = NULL) {
      assert_scalar_character(type)
      if (is.null(description)) {
        description <- ""
      } else {
        assert_scalar_character(description)
      }
      if (is.null(path)) {
        path <- type
      }
      if (!is.null(options)) {
        assert_named(options)
      }

      body <- drop_null(list(type = type,
                             description = description,
                             options = options))
      private$api_client$PUT(paste0("/sys/audit", prepare_path(path)),
                             body = body)
      invisible(NULL)
    },

    ##' @description Disable an audit device
    ##'
    ##' @param path Path of the audit device to remove
    disable = function(path) {
      private$api_client$DELETE(paste0("/sys/audit", prepare_path(path)))
      invisible(NULL)
    },

    ##' @description The `hash` method is used to calculate the hash of the
    ##'   data used by an audit device's hash function and salt. This can be
    ##'   used to search audit logs for a hashed value when the original
    ##'   value is known.
    ##'
    ##' @param input The input string to hash
    ##'
    ##' @param device The path of the audit device
    hash = function(input, device) {
      assert_scalar_character(input)
      body <- list(input = input)
      path <- paste0("/sys/audit-hash", prepare_path(device))
      private$api_client$POST(path, body = body)$hash
    }
  ))

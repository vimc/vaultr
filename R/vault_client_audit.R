##' Interact with vault's audit devices.  For more details, see
##' \url{https://www.vaultproject.io/docs/audit/}
##'
##' @template vault_client_audit
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
NULL


vault_client_audit <- R6::R6Class(
  "vault_client_audit",
  inherit = vault_client_object,
  cloneable = FALSE,

  private = list(api_client = NULL),

  public = list(
    initialize = function(api_client) {
      super$initialize("Interact with vault's audit devices")
      private$api_client <- api_client
    },

    list = function() {
      dat <- private$api_client$GET("/sys/audit")
      cols <- c("path", "type", "description")
      ret <- lapply(cols, function(v)
        vcapply(dat$data, "[[", v, USE.NAMES = FALSE))
      names(ret) <- cols
      as.data.frame(ret, stringsAsFactors = FALSE, check.names = FALSE)
    },

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

    disable = function(path) {
      private$api_client$DELETE(paste0("/sys/audit", prepare_path(path)))
      invisible(NULL)
    },

    hash = function(input, device) {
      assert_scalar_character(input)
      body <- list(input = input)
      path <- paste0("/sys/audit-hash", prepare_path(device))
      private$api_client$POST(path, body = body)$hash
    }
  ))

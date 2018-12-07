R6_vault_client_audit <- R6::R6Class(
  "vault_client_audit",

  private = list(api_client = NULL),

  public = list(
    initialize = function(api_client) {
      private$api_client <- api_client
    },

    format = function(brief = FALSE) {
      vault_client_format(self, brief, "audit",
                          "Interact with vault's audit devices")
    },

    list = function(detailed = FALSE) {
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
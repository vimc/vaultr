R6_vault_client_kv1 <- R6::R6Class(
  "vault_client_kv1",

  private = list(
    api_client = NULL,
    mount = NULL,

    validate_path = function(path) {
      path <- sub("^/", "", path)
      if (is.null(private$mount)) {
        return(path)
      }
      if (!string_starts_with(path, private$mount)) {
        stop(sprintf(
          "Invalid mount given for this path - expected '%s'", private$mount),
          call. = FALSE)
      }
      path
    }
  ),

  public = list(
    initialize = function(api_client, mount) {
      private$api_client <- api_client
      if (!is.null(mount)) {
        private$mount <- sub("^/", "", mount)
      }
    },

    format = function(brief = FALSE) {
      vault_client_format(self, brief, "kv1",
                          "Interact with vault's key/value store (version 1)")
    },

    custom_mount = function(mount) {
      R6_vault_client_kv1$new(private$api_client, mount)
    },

    read = function(path, field = NULL, metadata = FALSE) {
      path <- private$validate_path(path)
      res <- tryCatch(
        private$api_client$GET(path),
        vault_invalid_path = function(e) NULL)

      if (is.null(res)) {
        ret <- NULL
      } else {
        ret <- res$data
        if (!is.null(field)) {
          assert_scalar_character(field)
          ret <- res$data[[field]]
        } else if (metadata) {
          attr <- res[setdiff(names(res), "data")]
          attr(ret, "metadata") <- attr[lengths(attr) > 0]
        }
      }
      ret
    },

    write = function(path, data) {
      path <- private$validate_path(path)
      assert_named(data)
      private$api_client$POST(path, body = data)
      invisible(NULL)
    },

    list = function(path, full_names = FALSE) {
      path <- private$validate_path(path)
      dat <- tryCatch(
        private$api_client$LIST(path),
        vault_invalid_path = function(e) NULL)
      ret <- list_to_character(dat$data$keys)
      if (full_names) {
        ret <- file.path(sub("/+$", "", path), ret)
      }
      ret
    },

    delete = function(path) {
      path <- private$validate_path(path)
      private$api_client$DELETE(path)
      invisible(NULL)
    }
  ))

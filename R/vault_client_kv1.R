##' Interact with vault's version 1 key-value store.  This is useful
##' for storing simple key-value data without versioning or metadata
##' (see \code{\link{vault_client_kv2}} for a richer key-value store).
##'
##' Up to vault version 0.12.0 this was mounted by default at
##' \code{/secret}.  It can be accessed from vault with either the
##' \code{$read}, \code{$write}, \code{$list} and \code{$delete}
##' methods on the main \code{\link{vault_client}} object or by the
##' \code{$kv1} member of the
##' \code{\link[=vault_client_secrets]{secrets}} member of the main
##' vault client.
##'
##' @template vault_client_kv1
##'
##' @title Key-Value Store (Version 1)
##' @name vault_client_kv1
##' @examples
##'
##' server <- vaultr::vault_test_server(if_disabled = message)
##' if (!is.null(server)) {
##'   client <- server$client()
##'
##'   # Write secrets
##'   client$secrets$kv1$write("/secret/path/mysecret", list(key = "value"))
##'
##'   # List secrets - note the trailing "/" indicates a folder
##'   client$secrets$kv1$list("/secret")
##'   client$secrets$kv1$list("/secret/path")
##'
##'   # Read secrets
##'   client$secrets$kv1$read("/secret/path/mysecret")
##'   client$secrets$kv1$read("/secret/path/mysecret", field = "key")
##'
##'   # Delete secrets
##'   client$secrets$kv1$delete("/secret/path/mysecret")
##'   client$secrets$kv1$read("/secret/path/mysecret")
##'
##'   # cleanup
##'   server$kill()
##' }
vault_client_kv1 <- R6::R6Class(
  "vault_client_kv1",
  inherit = vault_client_object,
  cloneable = FALSE,

  private = list(
    api_client = NULL,
    mount = NULL
  ),

  public = list(
    initialize = function(api_client, mount) {
      super$initialize("Interact with vault's key/value store (version 1)")
      private$api_client <- api_client
      if (!is.null(mount)) {
        private$mount <- sub("^/", "", mount)
      }
    },

    ##' @description Set up a `vault_client_kv1` object at a custom
    ##'   mount.  For example, suppose you mounted another copy of the
    ##'   `kv1` secret backend at `/secret2` you might use `kv <-
    ##'   vault$secrets$kv1$custom_mount("/secret2")` - this pattern is
    ##'   repeated for other secret and authentication backends.
    ##'
    ##' @param mount String, indicating the path that the engine is
    ##'   mounted at.
    custom_mount = function(mount) {
      vault_client_kv1$new(private$api_client, mount)
    },

    ##' @description Read a value from the vault.  This can be used to
    ##'   read any value that you have permission to read in this
    ##'   store.
    ##'
    ##' @param path Path for the secret to read, such as
    ##'    `/secret/mysecret`
    ##'
    ##' @param field Optional field to read from the secret.  Each
    ##'   secret is stored as a key/value set (represented in R as a
    ##'   named list) and this is equivalent to using `[[field]]` on
    ##'   the return value.  The default, `NULL`, returns the full set
    ##'   of values.
    ##'
    ##' @param metadata Logical, indicating if we should return
    ##'   metadata for this secret (lease information etc) as an
    ##'   attribute along with the values itself.  Ignored if `field`
    ##'   is specified.
    read = function(path, field = NULL, metadata = FALSE) {
      vault_kv_read(private$api_client, private$mount, path, field, metadata)
    },

    ##' @description Write data into the vault.  This can be used to
    ##'   write any value that you have permission to write in this
    ##'   store.
    ##'
    ##' @param path Path for the secret to write, such as
    ##'   `/secret/mysecret`
    ##'
    ##' @param data A named list of values to write into the vault at
    ##'   this path.  This *replaces* any existing values.
    write = function(path, data) {
      vault_kv_write(private$api_client, private$mount, path, data)
    },

    ##' @description List data in the vault at a give path.  This can
    ##'     be used to list keys, etc (e.g., at `/secret`).
    ##'
    ##' @param path The path to list
    ##'
    ##' @param full_names Logical, indicating if full paths (relative
    ##'   to the vault root) should be returned.
    ##'
    ##' @param value A character vector (of zero length if no keys are
    ##'   found).  Paths that are "directories" (i.e., that contain
    ##'   keys and could themselves be listed) will be returned with a
    ##'   trailing forward slash, e.g. `path/`
    list = function(path, full_names = FALSE) {
      vault_kv_list(private$api_client, private$mount, path, full_names)
    },

    ##' @description Delete a value from the vault
    ##'
    ##' @param path The path to delete
    delete = function(path) {
      vault_kv_delete(private$api_client, private$mount, path)
    }
  ))


vault_kv_read <- function(api_client, mount, path, field = NULL,
                          metadata = FALSE) {
  path <- vault_validate_path(path, mount)
  res <- tryCatch(
    api_client$GET(path),
    vault_invalid_path = function(e) NULL,
    error = function(e) {
      e$message <- sprintf("While reading %s:\n %s", path, e$message)
      stop(e)
    })

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
}


vault_kv_write <- function(api_client, mount, path, data) {
  path <- vault_validate_path(path, mount)
  assert_named(data)
  api_client$POST(path, body = data)
  invisible(NULL)
}


vault_kv_list <- function(api_client, mount, path, full_names = FALSE) {
  path <- vault_validate_path(path, mount)
  dat <- tryCatch(
    api_client$LIST(path),
    vault_invalid_path = function(e) NULL)
  ret <- list_to_character(dat$data$keys)
  if (full_names) {
    ret <- paste(sub("/+$", "", path), ret, sep = "/")
  }
  ret
}


vault_kv_delete <- function(api_client, mount, path) {
  api_client$DELETE(path)
  invisible(NULL)
}


vault_validate_path <- function(path, mount) {
  path <- sub("^/", "", path)
  if (is.null(mount)) {
    return(path)
  }
  if (!string_starts_with(path, mount)) {
    stop(sprintf(
      "Invalid mount given for this path - expected '%s'", mount),
      call. = FALSE)
  }
  path
}

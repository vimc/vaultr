##' Interact with vault's cubbyhole key-value store.  This is useful
##' for storing simple key-value data without versioning or metadata
##' (c.f. \code{\link{vault_client_kv2}}) that is scoped to your
##' current token only and not accessible to anyone else.  For more
##' details please see the vault documentation
##' \url{https://www.vaultproject.io/docs/secrets/cubbyhole/index.html}
##'
##' @template vault_client_cubbyhole
##'
##' @title Cubbyhole secret store
##' @name vault_client_cubbyhole
##'
##' @examples
##'
##' server <- vaultr::vault_test_server(if_disabled = message)
##' if (!is.null(server)) {
##'   client <- server$client()
##'
##'   # Shorter path for easier reading:
##'   cubbyhole <- client$secrets$cubbyhole
##'   cubbyhole
##'
##'   # Write a value
##'   cubbyhole$write("cubbyhole/secret", list(key = "value"))
##'   # List it
##'   cubbyhole$list("cubbyhole")
##'   # Read it
##'   cubbyhole$read("cubbyhole/secret")
##'   # Delete it
##'   cubbyhole$delete("cubbyhole/secret")
##'
##'   # cleanup
##'   server$kill()
##' }
vault_client_cubbyhole <- R6::R6Class(
  "vault_client_cubbyhole",
  inherit = vault_client_object,
  cloneable = FALSE,

  private = list(
    api_client = NULL,
    mount = "cubbyhole"
  ),

  public = list(
    initialize = function(api_client) {
      super$initialize("Interact with vault's cubbyhole secret backend")
      private$api_client <- api_client
    },

    ##' @description Read a value from your cubbyhole
    ##'
    ##' @param path Path for the secret to read, such as
    ##'   `/cubbyhole/mysecret`
    ##'
    ##' @param field Optional field to read from the secret.  Each
    ##'   secret is stored as a key/value set (represented in R as a
    ##'   named list) and this is equivalent to using `[[field]]`
    ##'   on the return value.  The default, `NULL`, returns the
    ##'   full set of values.
    ##'
    ##' @param metadata Logical, indicating if we should return
    ##'   metadata for this secret (lease information etc) as an
    ##'   attribute along with the values itself.  Ignored if
    ##'   `field` is specified.
    read = function(path, field = NULL, metadata = FALSE) {
      vault_kv_read(private$api_client, private$mount, path, field, metadata)
    },

    ##' @description Write data into your cubbyhole.
    ##'
    ##' @param path Path for the secret to write, such as
    ##'   `/cubbyhole/mysecret`
    ##'
    ##' @param data A named list of values to write into the vault at
    ##'   this path.  This *replaces* any existing values.
    write = function(path, data) {
      vault_kv_write(private$api_client, private$mount, path, data)
    },

    ##' @description List data in the vault at a give path.  This can
    ##'   be used to list keys, etc (e.g., at `/cubbyhole`).
    ##'
    ##' @param path The path to list
    ##'
    ##' @param full_names Logical, indicating if full paths (relative
    ##'       to the vault root) should be returned.
    ##'
    ##' @param value A character vector (of zero length if no keys are
    ##'     found).  Paths that are "directories" (i.e., that contain
    ##'     keys and could themselves be listed) will be returned with
    ##'     a trailing forward slash, e.g. `path/`
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

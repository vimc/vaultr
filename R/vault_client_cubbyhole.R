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
NULL

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

    read = function(path, field = NULL, metadata = FALSE) {
      vault_kv_read(private$api_client, private$mount, path, field, metadata)
    },

    write = function(path, data) {
      vault_kv_write(private$api_client, private$mount, path, data)
    },

    list = function(path, full_names = FALSE) {
      vault_kv_list(private$api_client, private$mount, path, full_names)
    },

    delete = function(path) {
      vault_kv_delete(private$api_client, private$mount, path)
    }
  ))

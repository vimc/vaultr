##' Interact with vault's version 2 key-value store.  This is useful
##' for storing simple key-value data that can be versioned and for
##' storing metadata alongside the secrets (see
##' [vaultr::vault_client_kv1] for a simpler key-value store, and see
##' https://www.vaultproject.io/docs/secrets/kv/kv-v2.html for
##' detailed information about this secret store.
##'
##' A `kv2` store can be mounted anywhere, so all methods accept
##' a `mount` argument.  This is different to the CLI which lets
##' you try and read values from any vault path, but similar to other
##' secret and auth backends which accept arguments like
##' `-mount-point`.  So if the `kv2` store is mounted at
##' `/project-secrets` for example, with a vault client
##' `vault` one could write
##'
##' ```
##' vault$secrets$kv2$get("/project-secrets/mysecret",
##'                       mount = "project-secrets")
##' ```
##'
##' or
##'
##' ```
##' kv2 <- vault$secrets$kv2$custom_mount("project-secrets")
##' kv2$get("mysecret")
##' ```
##'
##' If the leading part of of a path to secret within a `kv2`
##' store does not match the mount point, `vaultr` will throw an
##' error.  This approach results in more predictable error messages,
##' though it is a little more typing than for the CLI vault client.
##'
##' @title Key-Value Store (Version 2)
##' @name vault_client_kv2
##' @examples
##'
##' server <- vaultr::vault_test_server(if_disabled = message)
##' if (!is.null(server)) {
##'   client <- server$client()
##'   # With the test server as created by vaultr, the kv2 storage
##'   # engine is not enabled.  To use the kv2 store we must first
##'   # enable it; the command below will add it at the path /kv on
##'   # our vault server
##'   client$secrets$enable("kv", version = 2)
##'
##'   # For ease of reading, create a 'kv' object for interacting with
##'   # the store (see below for the calls without this object)
##'   kv <- client$secrets$kv2$custom_mount("kv")
##'   kv$config()
##'
##'   # The version-2 kv store can be treated largely the same as the
##'   # version-1 store, though with slightly different command names
##'   # (put instead of write, get instead of read)
##'   kv$put("/kv/path/secret", list(key = "value"))
##'   kv$get("/kv/path/secret")
##'
##'   # But it also allows different versions to be stored at the same path:
##'   kv$put("/kv/path/secret", list(key = "s3cret!"))
##'   kv$get("/kv/path/secret")
##'
##'   # Old versions can be retrieved still:
##'   kv$get("/kv/path/secret", version = 1)
##'
##'   # And metadata about versions can be retrieved
##'   kv$metadata_get("/kv/path/secret")
##'
##'   # cleanup
##'   server$kill()
##' }
vault_client_kv2 <- R6::R6Class(
  "vault_client_kv2",
  inherit = vault_client_object,
  cloneable = FALSE,

  private = list(
    api_client = NULL,
    mount = NULL,

    validate_path = function(path, mount, zero_length_ok = FALSE) {
      path <- sub("^/", "", path)
      mount <- mount %||% private$mount

      if (!string_starts_with(path, mount)) {
        stop(sprintf(
          "Invalid mount given for this path - expected '%s'", mount))
      }
      relative <- substr(path, nchar(mount) + 2, nchar(path))

      if (!zero_length_ok && !nzchar(relative)) {
        stop("Invalid path")
      }

      list(mount = mount,
           relative = relative,
           data = sprintf("/%s/data/%s", mount, relative),
           metadata = sprintf("/%s/metadata/%s", mount, relative),
           delete = sprintf("/%s/delete/%s", mount, relative),
           undelete = sprintf("/%s/undelete/%s", mount, relative),
           destroy = sprintf("/%s/destroy/%s", mount, relative))
    },

    validate_version = function(version, multiple_allowed = FALSE) {
      if (is.null(version)) {
        NULL
      } else {
        if (multiple_allowed) {
          assert_integer(version)
          ## NOTE: The 'I' here is to stop httr "helpfully" unboxing
          ## length-1 arrays.  The alternative solution would be to
          ## manually convert to json, which is what we'll need to do
          ## if dropping httr in favour of plain curl
          list(versions = I(version))
        } else {
          assert_scalar_integer(version)
          list(version = version)
        }
      }
    }
  ),

  public = list(
    ##' @description Create a `vault_client_kv2` object. Not typically
    ##'   called by users.
    ##'
    ##' @param api_client A [vaultr::vault_api_client] object
    ##'
    ##' @param mount Mount point for the backend
    initialize = function(api_client, mount) {
      super$initialize("Interact with vault's key/value store (version 2)")
      assert_scalar_character(mount)
      private$mount <- sub("^/", "", mount)
      private$api_client <- api_client
    },

    ##' @description Fetch the configuration for this `kv2` store.
    ##'     Returns a named list of values, the contents of which will
    ##'     depend on the vault version.
    ##'
    ##' @param mount Custom mount path to use for this store (see `Details`).
    config = function(mount = NULL) {
      path <- sprintf("%s/config", mount %||% private$mount)
      private$api_client$GET(path)$data
    },

    ##' @description Set up a `vault_client_kv2` object at a custom
    ##'   mount.  For example, suppose you mounted another copy of the
    ##'   `kv2` secret backend at `/secret2` you might use `kv <-
    ##'   vault$secrets$kv2$custom_mount("/secret2")` - this pattern is
    ##'   repeated for other secret and authentication backends.
    ##'
    ##' @param mount String, indicating the path that the engine is
    ##' mounted at.
    custom_mount = function(mount) {
      vault_client_kv2$new(private$api_client, mount)
    },

    ##' @description Delete a secret from the vault.  This marks the
    ##'   version as deleted and will stop it from being returned from
    ##'   reads, but the underlying data will not be removed. A delete
    ##'   can be undone using the undelete method.
    ##'
    ##' @param path Path to delete
    ##'
    ##' @param version Optional version to delete.  If `NULL` (the
    ##'   default) then the latest version of the secret is deleted.
    ##'   Otherwise, `version` can be a vector of integer versions to
    ##'   delete.
    ##'
    ##' @param mount Custom mount path to use for this store (see `Details`).
    delete = function(path, version = NULL, mount = NULL) {
      path <- private$validate_path(path, mount)
      if (is.null(version)) {
        private$api_client$DELETE(path$data)
      } else {
        body <- private$validate_version(version, TRUE)
        private$api_client$POST(path$delete, body = body)
      }
      invisible(NULL)
    },

    ##' @description Delete a secret entirely.  Unlike `delete` this
    ##'   operation is irreversible and is more like the `delete`
    ##'   operation on [`vaultr::vault_client_kv1`] stores.
    ##'
    ##' @param path Path to delete
    ##'
    ##' @param version Version numbers to delete, as a vector of
    ##'   integers (this is required)
    ##'
    ##' @param mount Custom mount path to use for this store (see `Details`).
    destroy = function(path, version, mount = NULL) {
      path <- private$validate_path(path, mount)
      body <- private$validate_version(version, TRUE)
      private$api_client$POST(path$destroy, body = body)
      invisible(NULL)
    },

    ##' @description Read a secret from the vault
    ##'
    ##' @param path Path of the secret to read
    ##'
    ##' @param version Optional version of the secret to read.  If
    ##'   `NULL` (the default) then the most recent version is read.
    ##'   Otherwise this must be a scalar integer.
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
    ##'
    ##' @param mount Custom mount path to use for this store (see `Details`).
    get = function(path, version = NULL, field = NULL,
                   metadata = FALSE, mount = NULL) {
      path <- private$validate_path(path, mount)
      query <- private$validate_version(version)
      assert_scalar_logical(metadata)
      assert_scalar_character_or_null(field)

      res <- tryCatch(
        private$api_client$GET(path$data, query = query),
        vault_invalid_path = function(e) NULL)

      if (is.null(res)) {
        return(NULL)
      }

      ret <- res$data$data
      if (!is.null(field)) {
        ret <- ret[[field]]
      } else if (metadata) {
        attr(ret, "metadata") <- res$data$metadata
      }
      ret
    },

    ##' @description List data in the vault at a give path.  This can
    ##'   be used to list keys, etc (e.g., at `/secret`).
    ##'
    ##' @param path The path to list
    ##'
    ##' @param full_names Logical, indicating if full paths (relative
    ##'   to the vault root) should be returned.
    ##'
    ##' @param mount Custom mount path to use for this store (see `Details`).
    ##'
    ##' @param value A character vector (of zero length if no keys are
    ##'   found).  Paths that are "directories" (i.e., that contain
    ##'   keys and could themselves be listed) will be returned with a
    ##'   trailing forward slash, e.g. `path/`
    list = function(path, full_names = FALSE, mount = NULL) {
      ## TODO: support full_names here?
      path <- private$validate_path(path, mount, TRUE)
      res <- tryCatch(
        private$api_client$LIST(path$metadata),
        vault_invalid_path = function(e) NULL)
      ret <- list_to_character(res$data$keys)
      if (full_names) {
        ret <- paste(sub("/+$", "", path$mount), ret, sep = "/")
      }
      ret
    },

    ##' @description Read secret metadata and versions at the specified
    ##'   path
    ##'
    ##' @param path Path of secret to read metadata for
    ##'
    ##' @param mount Custom mount path to use for this store (see `Details`).
    metadata_get = function(path, mount = NULL) {
      path <- private$validate_path(path, mount)
      res <- tryCatch(
        private$api_client$GET(path$metadata),
        vault_invalid_path = function(e) NULL)
      if (is.null(res)) {
        return(NULL)
      }
      res$data
    },

    ##' @description Update metadata for a secret.  This is allowed
    ##'   even if a secret does not yet exist, though this requires the
    ##'   `create` vault permission at this path.
    ##'
    ##' @param path Path of secret to update metadata for
    ##'
    ##' @param cas_required Logical, indicating that if If true the key
    ##'   will require the cas parameter to be set on all write
    ##'   requests (see `put`). If `FALSE`, the backend's configuration
    ##'   will be used.
    ##'
    ##' @param max_versions Integer, indicating the
    ##'   maximum number of versions to keep per key.  If not set, the
    ##'   backend's configured max version is used. Once a key has more
    ##'   than the configured allowed versions the oldest version will
    ##'   be permanently deleted.
    ##'
    ##' @param mount Custom mount path to use for this store (see `Details`).
    metadata_put = function(path, cas_required = NULL, max_versions = NULL,
                              mount = NULL) {
      path <- private$validate_path(path, mount)
      body <- drop_null(list(
        cas_required = cas_required, max_versions = max_versions))
      private$api_client$POST(path$metadata, body = body)
      invisible(NULL)
    },

    ##' @description This method permanently deletes the key metadata
    ##'   and all version data for the specified key. All version
    ##'   history will be removed.
    ##'
    ##' @param path Path to delete
    ##'
    ##' @param mount Custom mount path to use for this store (see `Details`).
    metadata_delete = function(path, mount = NULL) {
      path <- private$validate_path(path, mount)
      private$api_client$DELETE(path$metadata)
      invisible(NULL)
    },

    ##' @description Create or update a secret in this store.
    ##'
    ##' @param path Path for the secret to write, such as
    ##'   `/secret/mysecret`
    ##'
    ##' @param data A named list of values to write into the vault at
    ##'    this path.
    ##'
    ##' @param cas Integer, indicating the "cas" value to use a
    ##'   "Check-And-Set" operation. If not set the write will be
    ##'   allowed. If set to 0 a write will only be allowed if the key
    ##'   doesn't exist. If the index is non-zero the write will only
    ##'   be allowed if the key's current version matches the version
    ##'   specified in the cas parameter.
    ##'
    ##' @param mount Custom mount path to use for this store (see `Details`).
    put = function(path, data, cas = NULL, mount = NULL) {
      assert_named(data)
      body <- list(data = data)
      if (!is.null(cas)) {
        assert_scalar_integer(cas)
        body$options <- list(cas = cas)
      }
      path <- private$validate_path(path, mount)
      ret <- private$api_client$POST(path$data, body = body)
      invisible(ret$data)
    },

    ## TODO: implement patch
    ## patch = function(...) {
    ##   stop("not implemented")
    ## },

    ##' @description Undeletes the data for the provided version and
    ##'   path in the key-value store. This restores the data, allowing
    ##'   it to be returned on get requests.  This works with data
    ##'   deleted with `$delete` but not with `$destroy`.
    ##'
    ##' @param path The path to undelete
    ##'
    ##' @param version Integer vector of versions to undelete
    ##'
    ##' @param mount Custom mount path to use for this store (see `Details`).
    undelete = function(path, version, mount = NULL) {
      path <- private$validate_path(path, mount)
      body <- private$validate_version(version, TRUE)
      private$api_client$POST(path$undelete, body = body)
      invisible(NULL)
    }
  ))

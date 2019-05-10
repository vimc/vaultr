##' Interact with vault's version 2 key-value store.  This is useful
##' for storing simple key-value data that can be versioned and store
##' metadata alongside the secrets (see \code{\link{vault_client_kv1}}
##' for a simpler key-value store.
##'
##' A \code{kv2} store can be mounted anywhere, so all methods accept
##' a \code{mount} argument.  This is different to the CLI which lets
##' you try and read values from any vault path, but similar to other
##' secret and auth backends which accept arguments like
##' \code{-mount-point}.  So if the \code{kv2} store is mounted at
##' \code{/project-secrets} for example, with a vault client
##' \code{vault} one could write
##'
##' \preformatted{
##' vault$secrets$kv2$get("/project-secrets/mysecret",
##'                       mount = "project-secrets")
##' }
##'
##' or
##'
##' \preformatted{
##' kv2 <- vault$secrets$kv2$custom_mount("project-secrets")
##' kv2$get("mysecret")
##' }
##'
##' If the leading part of of a path to secret within a \code{kv2}
##' store does not match the mount point, \code{vaultr} will throw an
##' error.  This approach results in more predictable error messages,
##' though it is a little more typing than for the CLI vault client.
##'
##' @template vault_client_kv2
##'
##' @title Key-Value Store (Version 2)
##' @name vault_client_kv2
NULL


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
    initialize = function(api_client, mount) {
      super$initialize("Interact with vault's key/value store (version 2)")
      assert_scalar_character(mount)
      private$mount <- sub("^/", "", mount)
      private$api_client <- api_client
    },

    config = function(mount = NULL) {
      path <- sprintf("%s/config", mount %||% private$mount)
      private$api_client$GET(path)
    },

    custom_mount = function(mount) {
      vault_client_kv2$new(private$api_client, mount)
    },

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

    destroy = function(path, version, mount = NULL) {
      path <- private$validate_path(path, mount)
      body <- private$validate_version(version, TRUE)
      private$api_client$POST(path$destroy, body = body)
      invisible(NULL)
    },

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

    metadata_put = function(path, cas_required = NULL, max_versions = NULL,
                              mount = NULL) {
      path <- private$validate_path(path, mount)
      body <- drop_null(list(
        cas_required = cas_required, max_versions = max_versions))
      private$api_client$POST(path$metadata, body = body)
      invisible(NULL)
    },

    metadata_delete = function(path, mount = NULL) {
      path <- private$validate_path(path, mount)
      private$api_client$DELETE(path$metadata)
      invisible(NULL)
    },

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

    undelete = function(path, version, mount = NULL) {
      path <- private$validate_path(path, mount)
      body <- private$validate_version(version, TRUE)
      private$api_client$POST(path$undelete, body = body)
      invisible(NULL)
    }
  ))

## For the first shot at refactoring,
##
## * we use the silly name 'vault_client2' which will eventually
##   replace vault_client
##
## * no attempt at backward compatibility - we'll see how the tests go
##   and work through from there.
vault_client2 <- function(addr = NULL, tls_config = NULL) {
  R6_vault_client2$new(addr, tls_config)
}


R6_vault_client2 <- R6::R6Class(
  "vault_client",

  cloneable = FALSE,

  private = list(
    api_client = NULL),

  public = list(
    auth = NULL,
    audit = NULL,
    kv = NULL,
    lease = NULL,
    operator = NULL,
    policy = NULL,
    secrets = NULL,
    token = NULL,

    initialize = function(addr, tls_config) {
      api_client <- vault_api_client$new(addr, tls_config)

      private$api_client <- api_client

      self$auth <- R6_vault_client_auth$new(api_client)
      self$audit <- R6_vault_client_audit$new(api_client)
      self$kv <- R6_vault_client_kv$new(api_client, "secret")
      self$lease <- R6_vault_client_lease$new(api_client)
      self$operator <- R6_vault_client_operator$new(api_client)
      self$policy <- R6_vault_client_policy$new(api_client)
      self$secrets <- R6_vault_client_secrets$new(api_client)
      self$token <- R6_vault_client_token$new(api_client)
    },

    format = function(brief = FALSE) {
      vault_client_format(self, brief, "base",
                          "core methods for interacting with vault")
    },

    ## Basic methods:
    read = function(path, field = NULL, info = FALSE) {
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
        } else if (info) {
          attr <- res[setdiff(names(res), "data")]
          attr(ret, "info") <- attr[lengths(attr) > 0]
        }
      }
      ret
    },

    write = function(path, data) {
      assert_named(data)
      res <- private$api_client$POST(path, body = data, to_json = FALSE)
      if (httr::status_code(res) == 200) {
        response_to_json(res)
      } else {
        invisible(NULL)
      }
    },

    delete = function(path) {
      private$api_client$DELETE(path, to_json = FALSE)
      invisible(NULL)
    },

    ## NOTE: no recursive list here
    list = function(path, full_names = FALSE) {
      root <- sub("/+$", "", path)

      dat <- tryCatch(
        private$api_client$GET(path, query = list(list = TRUE)),
        vault_invalid_path = function(e) NULL)

      ret <- list_to_character(dat$data$keys)

      if (full_names) {
        ret <- file.path(root, ret)
      }

      ret
    },

    login = function(..., method = "token", renew = FALSE, quiet = FALSE,
                     token_only = FALSE) {
      do_auth <- renew || token_only || !private$api_client$is_authenticated()
      if (do_auth) {
        token <- vault_login(private$api_client, method, quiet, ...)
      } else {
        token <- NULL
      }
      if (!token_only) {
        private$api_client$set_token(token, verify = FALSE)
      }
      invisible(token)
    },

    status = function() {
      private$api_client$GET("/sys/seal-status", allow_missing_token = TRUE)
    },

    upwrap = function(...) {
      stop("unwrap not yet implemented")
    }
  ))


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
    }
  ))


## Interact with auth methods.  This is an administrative command.
R6_vault_client_auth <- R6::R6Class(
  "vault_client_auth",

  private = list(api_client = NULL),

  public = list(
    initialize = function(api_client) {
      private$api_client <- api_client
    },

    format = function(brief = FALSE) {
      vault_client_format(self, brief, "auth",
                          "administer vault's authentication methods")
    },

    list = function(detailed = FALSE) {
      if (detailed) {
        stop("Detailed auth information not supported")
      }
      dat <- private$api_client$GET("/sys/auth")

      cols <- c("type", "accessor", "description")

      ret <- lapply(cols, function(v)
        vapply(dat$data, "[[", "", v, USE.NAMES = FALSE))
      names(ret) <- cols

      ## TODO: empty strings here might be better as NA
      as.data.frame(c(list(path = names(dat$data)), ret),
                    stringsAsFactors = FALSE, check.names = FALSE)
    },

    enable = function(type, description = NULL, local = FALSE,
                      path = NULL, plugin_name = NULL) {
      assert_scalar_character(type)
      if (is.null(description)) {
        description <- ""
      } else {
        assert_scalar_character(description)
      }
      assert_scalar_logical(local)
      if (is.null(path)) {
        path <- type
      }
      assert_scalar_character_or_null(plugin_name)

      data <- drop_null(list(type = type,
                             description = description,
                             local = local,
                             plugin_name = plugin_name))
      private$api_client$POST(paste0("/sys/auth/", path),
                            body = data, to_json = FALSE)
      invisible(NULL)
    },

    disable = function(path) {
      private$api_client$DELETE(paste0("/sys/auth/", path), to_json = FALSE)
      invisible(NULL)
    }
  ))


R6_vault_client_kv <- R6::R6Class(
  "vault_client_kv",

  private = list(
    api_client = NULL,
    mount = NULL,

    validate_path = function(path, mount) {
      path <- sub("^/", "", path)
      mount <- mount %||% private$mount

      if (!string_starts_with(path, mount)) {
        stop(sprintf(
          "Invalid mount given for this path - expected '%s'", mount))
      }
      relative <- substr(path, nchar(mount) + 2, nchar(path))

      if (!nzchar(relative)) {
        stop("Invalid path")
      }

      list(mount = mount,
           relative = relative,
           data = sprintf("/%s/data/%s", mount, relative),
           metadata = sprintf("/%s/metadata/%s", mount, relative),
           delete = sprintf("/%s/delete/%s", mount, relative),
           undelete = sprintf("/%s/undelete/%s", mount, relative))
    },

    validate_version = function(version) {
      if (is.null(version)) {
        NULL
      } else {
        assert_scalar_integer(version)
        list(version = version)
      }
    }
  ),

  public = list(
    initialize = function(api_client, mount) {
      assert_scalar_character(mount)
      private$mount <- sub("^/", "", mount)
      private$api_client <- api_client
    },

    format = function(brief = FALSE) {
      vault_client_format(self, brief, "kv",
                          "Interact with vault's key/value store")
    },

    config = function(mount = NULL) {
      path <- sprintf("%s/config", mount %||% private$mount)
      private$api_client$GET(path)
    },

    custom_mount = function(mount) {
      R6_vault_client_kv$new(private$api_client, mount)
    },

    delete = function(path, version) {
      ## TODO: the cli supports 'versions' but what does that
      ## correspond to in the api?
      stop("not implemented")
    },

    destroy = function(path, version) {
      stop("not implemented")
    },

    ## enable-versioning

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

    list = function(...) {
      stop("not implemented")
    },

    metadata = function(...) {
      path <- private$validate_path(path, mount)
      query <- private$validate_version(version)
      data <- private$api_client$GET(path$data, query = query)

    },

    patch = function(...) {
      stop("not implemented")
    },

    put = function(path, data, cas = NULL, mount = NULL) {
      assert_named(data)
      body <- list(data = data)
      if (!is.null(cas)) {
        assert_scalar_integer(cas)
        body$options <- list(cas = cas)
      }
      path <- private$validate_path(path, mount)
      ret <- private$api_client$POST(path$data, body = body, to_json = TRUE)
      invisible(ret$data)
    },

    rollback = function(...) {
      stop("not implemented")
    },

    undelete = function(...) {
      stop("not implemented")
    }
  ))


R6_vault_client_lease <- R6::R6Class(
  "vault_client_lease",

  private = list(api_client = NULL),

  public = list(
    initialize = function(api_client) {
      private$api_client <- api_client
    },

    format = function(brief = FALSE) {
      vault_client_format(self, brief, "lease",
                          "Interact with leases")
    }
  ))


R6_vault_client_operator <- R6::R6Class(
  "vault_client_operator",

  private = list(api_client = NULL),

  public = list(
    initialize = function(api_client) {
      private$api_client <- api_client
    },

    format = function(brief = FALSE) {
      vault_client_format(self, brief, "operator",
                          "Administration commands for vault operators")
    }
  ))


R6_vault_client_policy <- R6::R6Class(
  "vault_client_policy",

  private = list(api_client = NULL),

  public = list(
    initialize = function(api_client) {
      private$api_client <- api_client
    },

    format = function(brief = FALSE) {
      vault_client_format(self, brief, "policy",
                          "Interact with policies")
    }
  ))


R6_vault_client_secrets <- R6::R6Class(
  "vault_client_secrets",

  private = list(api_client = NULL),

  public = list(
    initialize = function(api_client) {
      private$api_client <- api_client
    },

    format = function(brief = FALSE) {
      vault_client_format(self, brief, "secrets",
                          "Interact with secret engines")
    },

    disable = function(path) {
      if (!is_absolute_path(path)) {
        path <- paste0("/", path)
      }
      private$api_client$DELETE(paste0("/sys/mounts", path), to_json = FALSE)
      invisible(NULL)
    },

    enable = function(type, path = type, description = NULL, version = NULL) {
      ## TODO: there are many additional options here that are not
      ## currently supported and which would come through the "config"
      ## argument.
      assert_scalar_character(type)
      assert_scalar_character(path)
      assert_scalar_character_or_null(description)

      if (!is_absolute_path(path)) {
        path <- paste0("/", path)
      }
      data <- list(type = type,
                   description = description)
      if (!is.null(version)) {
        data$options <- list(version = as.character(version))
      }
      private$api_client$POST(paste0("/sys/mounts", path),
                              body = data, to_json = FALSE)
      invisible(path)
    },

    list = function(detailed = FALSE) {
      if (detailed) {
        stop("Detailed auth information not supported")
      }
      dat <- private$api_client$GET("/sys/mounts")
      cols <- c("type", "accessor", "description")
      ret <- lapply(cols, function(v)
        vapply(dat$data, "[[", "", v, USE.NAMES = FALSE))
      names(ret) <- cols
      as.data.frame(c(list(path = names(dat$data)), ret),
                    stringsAsFactors = FALSE, check.names = FALSE)
    }
  ))


R6_vault_client_token <- R6::R6Class(
  "vault_client_token",

  private = list(api_client = NULL),

  public = list(
    initialize = function(api_client) {
      private$api_client <- api_client
    },

    format = function(brief = FALSE) {
      vault_client_format(self, brief, "token",
                          "Interact with tokens")
    }
  ))


vault_client_format <- function(object, brief, name, description) {
  if (brief) {
    return(description)
  }
  nms <- setdiff(ls(object), c("format", "clone", "delete", "initialize"))
  fns <- vlapply(nms, function(x) is.function(object[[x]]))
  is_obj <- vlapply(nms, function(x) inherits(object[[x]], "R6"))

  calls <- vcapply(nms[fns], function(x) capture_args(object[[x]], x),
                   USE.NAMES = FALSE)
  if (any(is_obj)) {
    objs <- c(
      "  Command groups:",
      vcapply(nms[is_obj], function(x)
        sprintf("    %s: %s", x, object[[x]]$format(TRUE)),
        USE.NAMES = FALSE))
  } else {
    objs <- NULL
  }

  c(sprintf("<vault: %s>", name),
    objs,
    "  Commands:",
    calls)
}

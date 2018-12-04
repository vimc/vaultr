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
    tools = NULL,

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
      self$tools <- R6_vault_client_tools$new(api_client)
    },

    format = function(brief = FALSE) {
      vault_client_format(self, brief, "base",
                          "core methods for interacting with vault")
    },

    api = function() {
      private$api_client
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
      private$api_client$POST(path, body = data)
      invisible(NULL)
    },

    delete = function(path) {
      private$api_client$DELETE(path)
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

    login = function(..., method = "token", mount = NULL,
                     renew = FALSE, quiet = FALSE,
                     token_only = FALSE) {
      do_auth <-
        assert_scalar_logical(renew) ||
        assert_scalar_logical(token_only) ||
        !private$api_client$is_authenticated()
      if (!do_auth) {
        return(NULL)
      }

      assert_scalar_character(method)
      args <- list(...)
      assert_named(args, "...")

      if (method == "token") {
        if (length(args) != 1L) {
          stop("Invalid arguments to login with method = 'token'",
               call. = FALSE)
        }
        token <- args[[1]]
      } else {
        auth <- self$auth[[method]]
        if (!inherits(auth, "R6")) {
          stop(sprintf(
            "Unknown login method '%s' - must be one of %s",
            method, paste(squote(self$auth$methods()), collapse = ", ")),
            call. = FALSE)
        }
        if (!is.null(mount)) {
          auth <- auth$custom_mount(mount)
        }
        ## TODO: Feedback usage information here?
        data <- auth$login(...)
        if (!quiet) {
          message(pretty_lease(data$lease_duration))
        }
        token <- data$client_token
      }

      if (!token_only) {
        if (!quiet) {
          message("Verifying token")
        }
        private$api_client$set_token(token, verify = method == "token")
      }

      invisible(token)
    },

    status = function() {
      self$operator$seal_status()
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

    methods = function() {
      nms <- ls(self)
      i <- vlapply(nms, function(x) inherits(self[[x]], "R6"))
      sort(nms[i])
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
      private$api_client$POST(paste0("/sys/auth/", path), body = data)
      invisible(NULL)
    },

    disable = function(path) {
      private$api_client$DELETE(paste0("/sys/auth/", path))
      invisible(NULL)
    }),

  ## Build these just in time
  active = list(
    github = function() {
      R6_vault_client_auth_github$new(private$api_client, "github")
    },

    token = function() {
      R6_vault_client_token$new(private$api_client)
    },

    userpass = function() {
      R6_vault_client_auth_userpass$new(private$api_client, "userpass")
    }
  ))


R6_vault_client_kv <- R6::R6Class(
  "vault_client_kv",

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

    list = function(path, mount = NULL) {
      path <- private$validate_path(path, mount, TRUE)
      res <- tryCatch(
        private$api_client$LIST(path$metadata),
        vault_invalid_path = function(e) NULL)
      list_to_character(res$data$keys)
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

    patch = function(...) {
      stop("not implemented")
    },

    undelete = function(path, version, mount = NULL) {
      path <- private$validate_path(path, mount)
      body <- private$validate_version(version, TRUE)
      private$api_client$POST(path$undelete, body = body)
      invisible(NULL)
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
    },

    key_status = function() {
      private$api_client$GET("/sys/key-status")
    },

    is_initialized = function() {
      d <- private$api_client$GET("/sys/init", allow_missing_token = TRUE)
      d$initialized
    },

    init = function(secret_shares, secret_threshold) {
      ## TODO: pgp not supported here
      assert_scalar_integer(secret_shares)
      assert_scalar_integer(secret_threshold)
      body <- list(secret_shares = secret_shares,
                   secret_threshold = secret_threshold)
      res <- private$api_client$PUT("/sys/init", body = body,
                                    allow_missing_token = TRUE)
      res$keys <- list_to_character(res$keys)
      res$keys_base64 <- list_to_character(res$keys_base64)
      res
    },

    leader_status = function() {
      private$api_client$GET("/sys/leader")
    },

    rekey_status = function() {
      private$api_client$GET("/sys/rekey/init")
    },

    rekey_start = function(secret_shares, secret_threshold, pgp_keys = NULL,
                           backup = FALSE, require_verification = FALSE) {
      assert_scalar_integer(secret_shares)
      assert_scalar_integer(secret_threshold)
      if (!is.null(pgp_keys)) {
        assert_character(pgp_keys)
        assert_length(pgp_keys, secret_threshold)
      }
      assert_scalar_logical(backup)
      assert_scalar_logical(require_verification)
      body <- list(secret_shares = secret_shares,
                   secret_threshold = secret_threshold,
                   pgp_keys = unname(pgp_keys),
                   backup = backup,
                   require_verification = require_verification)
      ## TODO: this is incorrect in the vault api docs
      ans <- private$api_client$PUT("/sys/rekey/init", body = body)
      ans
    },

    rekey_cancel = function() {
      private$api_client$DELETE("/sys/rekey/init")
      invisible(NULL)
    },

    rekey_submit = function(key, nonce) {
      assert_scalar_character(key)
      assert_scalar_character(nonce)
      body <- list(key = key, nonce = nonce)
      ans <- private$api_client$PUT("/sys/rekey/update", body = body)
      if (isTRUE(ans$complete)) {
        ans$keys <- list_to_character(ans$keys)
        ans$keys_base64 <- list_to_character(ans$keys_base64)
      }
      ans
    },

    rotate = function() {
      private$api_client$PUT("/sys/rotate")
      invisible(NULL)
    },

    seal = function() {
      private$api_client$PUT("/sys/seal")
      invisible(NULL)
    },

    seal_status = function() {
      private$api_client$GET("/sys/seal-status", allow_missing_token = TRUE)
    },

    unseal = function(key, reset = FALSE) {
      assert_scalar_character(key)
      assert_scalar_logical(reset)
      body <- list(key = key, reset = reset)
      private$api_client$PUT("/sys/unseal", body = body,
                             allow_missing_token = TRUE)
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
    },

    delete = function(name) {
      assert_scalar_character(name)
      private$api_client$DELETE(paste0("/sys/policy/", name))
      invisible(NULL)
    },

    list = function() {
      dat <- private$api_client$GET("/sys/policy")
      list_to_character(dat$data$keys)
    },

    read = function(name) {
      assert_scalar_character(name)
      dat <- private$api_client$GET(paste0("/sys/policy/", name))
      dat$data$rules
    },

    write = function(name, rules) {
      assert_scalar_character(name)
      assert_scalar_character(rules)
      body <- list(rules = rules)
      private$api_client$PUT(paste0("/sys/policy/", name), body = body)
      invisible(NULL)
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
      private$api_client$DELETE(paste0("/sys/mounts", path))
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
      private$api_client$POST(paste0("/sys/mounts", path), body = data)
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
    },

    move = function(from, to) {
      assert_scalar_character(from)
      assert_scalar_character(to)
      body <- list(from = from, to = to)
      private$api_client$POST("/sys/remount", body = body)
      invisible(NULL)
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

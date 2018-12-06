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
    kv1 = NULL,
    kv2 = NULL,
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
      self$kv1 <- R6_vault_client_kv1$new(api_client, NULL)
      self$kv2 <- R6_vault_client_kv2$new(api_client, "secret")
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

    ## Root object kv1 methods
    read = function(path, field = NULL, metadata = FALSE) {
      self$kv1$read(path, field, metadata)
    },

    write = function(path, data) {
      self$kv1$write(path, data)
    },

    delete = function(path) {
      self$kv1$delete(path)
    },

    ## NOTE: no recursive list here
    list = function(path, full_names = FALSE) {
      self$kv1$list(path, full_names)
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

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
      self$kv <- R6_vault_client_kv$new(api_client)
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
      data <- drop_null(list(...))
      assert_named(data)
      token <- vault_login_info(method)(private$api_client, data, quiet)
      if (token_only) {
        token
      } else {
        private$api_client$set_token(token, verify = FALSE)
      }
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
      path <- dat$data

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

  private = list(api_client = NULL),

  public = list(
    initialize = function(api_client) {
      private$api_client <- api_client
    },

    format = function(brief = FALSE) {
      vault_client_format(self, brief, "kv",
                          "Interact with vault's key/value store")
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


## These functions all get client tokens in different ways - there are
## more of these - there should be a key/value one too.  I am not
## certain that any of these really need verification though aside
## from the plain token because everything else is going to go
## _through_ the vault anyway.  So perhaps we just check the first:
vault_token_token <- function(client, data, quiet) {
  token <- vault_arg(data$token, "VAULT_TOKEN")
  if (is.null(token)) {
    stop("token not found (check $VAULT_TOKEN environment variable)")
  }
  assert_scalar_character(token)
  if (!quiet) {
    message("Verifying token")
  }
  client$verify_token(token)
  token
}


vault_token_github <- function(client, data, quiet) {
  if (!quiet) {
    message("Authenticating using github...", appendLF = FALSE)
  }

  token <- vault_auth_github_token(data$token)
  res <- client$POST("/auth/github/login",
                     body = list(token = token),
                     allow_missing_token = TRUE)
  if (!quiet) {
    lease <- res$auth$lease_duration
    message(sprintf("ok, duration: %s s (%s)",
                    lease, prettyunits::pretty_sec(lease, TRUE)))
  }

  res$auth$client_token
}


vault_login_userpass <- function(client, data, quiet) {
  ## TODO: check that data contains both username and password
  ##
  ## TODO: get password using getPass in an interactive session, with
  ## a wrapper for ease of testing
  if (is.null(data$password)) {
    msg <- sprintf("Password for '%s': ", data$username)
    data$password <- read_password(msg)
  }
  assert_scalar_character(data$username, "username")
  assert_scalar_character(data$password, "password")

  path <- paste0("/auth/userpass/login/", data$username)
  data <- list(password = data$password)
  res <- client$POST(path, body = data, allow_missing_token = TRUE)

  if (!quiet) {
    lease <- res$auth$lease_duration
    message(sprintf("ok, duration: %s s (%s)",
                    lease, prettyunits::pretty_sec(lease, TRUE)))
  }

  res$auth$client_token
}


vault_login_info <- function(method) {
  vault_methods <- list(
    token = vault_token_token,
    github = vault_token_github,
    userpass = vault_login_userpass)
  ret <- vault_methods[[method]]
  if (is.null(ret)) {
    stop(sprintf("Authentication method '%s' not supported", method))
  }
  ret
}


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

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
        private$api_client$set_token(token, verify = method == "token",
                                     quiet = quiet)
      }

      invisible(token)
    },

    status = function() {
      self$operator$seal_status()
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

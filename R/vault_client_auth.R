##' Interact with vault's authentication backends.
##'
##' @template vault_client_auth
##'
##' @title Vault Authentication Configuration
##' @name vault_client_auth
NULL


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

    backends = function() {
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
      ## TODO: later versions include config etc

      ret <- lapply(cols, function(v)
        vapply(dat$data, "[[", "", v, USE.NAMES = FALSE))
      names(ret) <- cols

      ## TODO: empty strings here might be better as NA
      as.data.frame(c(list(path = names(dat$data)), ret),
                    stringsAsFactors = FALSE, check.names = FALSE)
    },

    ## TODO: not passing in config here
    enable = function(type, description = NULL, local = FALSE, path = NULL) {
      assert_scalar_character(type)
      if (is.null(description)) {
        description <- ""
      } else {
        assert_scalar_character(description)
      }
      if (is.null(path)) {
        path <- type
      }

      data <- drop_null(list(type = type,
                             description = description,
                             local = assert_scalar_logical(local)))
      private$api_client$POST(paste0("/sys/auth/", path), body = data)
      invisible(NULL)
    },

    disable = function(path) {
      private$api_client$DELETE(paste0("/sys/auth/", path))
      invisible(NULL)
    }),

  ## Build these just in time
  active = list(
    ## Tokens are somewhat special
    token = function() {
      R6_vault_client_token$new(private$api_client)
    },

    ## This set will grow out eventually
    github = function() {
      R6_vault_client_auth_github$new(private$api_client, "github")
    },

    userpass = function() {
      R6_vault_client_auth_userpass$new(private$api_client, "userpass")
    },

    approle = function() {
      R6_vault_client_auth_approle$new(private$api_client, "approle")
    }
  ))

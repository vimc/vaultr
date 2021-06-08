##' Interact with vault's authentication backends.
##'
##' @template vault_client_auth
##'
##' @title Vault Authentication Configuration
##' @name vault_client_auth
##'
##' @examples
##' server <- vaultr::vault_test_server(if_disabled = message)
##' if (!is.null(server)) {
##'   client <- server$client()
##'
##'   # List configured authentication backends
##'   client$auth$list()
##'
##'   # cleanup
##'   server$kill()
##' }
NULL


vault_client_auth <- R6::R6Class(
  "vault_client_auth",
  inherit = vault_client_object,
  cloneable = FALSE,

  private = list(api_client = NULL),

  public = list(
    ##' @field approle Interact with vault's AppRole authentication.  See
    ##'   [`vaultr::vault_client_auth_approle`] for more information.
    approle = NULL,

    ##' @field github Interact with vault's GitHub authentication.  See
    ##'   [`vaultr::vault_client_auth_github`] for more information.
    github = NULL,

    ##' @field token Interact with vault's token authentication.  See
    ##'   [`vaultr::vault_client_token`] for more information.
    token = NULL,

    ##' @field userpass Interact with vault's username/password based
    ##' authentication.  See [`vaultr::vault_client_auth_userpass`] for
    ##' more information.
    userpass = NULL,

    initialize = function(api_client) {
      super$initialize("administer vault's authentication methods")
      private$api_client <- api_client

      add_const_member(
        self, "token",
        vault_client_token$new(private$api_client))
      add_const_member(
        self, "github",
        vault_client_auth_github$new(private$api_client, "github"))
      add_const_member(
        self, "userpass",
        vault_client_auth_userpass$new(private$api_client, "userpass"))
      add_const_member(
        self, "approle",
        vault_client_auth_approle$new(private$api_client, "approle"))
    },

    ##' @description Return a character vector of supported
    ##'   authentication backends.  If a backend `x` is present, then
    ##'   you can access it with `$auth$x`.  Note that vault calls
    ##'   these authentication *methods* but we use *backends* here to
    ##'   differentiate with R6 methods.  Note that these are backends
    ##'   supported by `vaultr` and not necessarily supported by the
    ##'   server - the server may not have enabled some of these
    ##'   backends, and may support other authentication backends not
    ##'   directly supported by vaultr.  See the `$list()` method to
    ##'   query what the server supports.
    backends = function() {
      nms <- ls(self)
      i <- vlapply(nms, function(x) inherits(self[[x]], "R6"))
      sort(nms[i])
    },

    ##' @description List authentication backends supported by the
    ##'   vault server, including information about where these
    ##'   backends are mounted.
    ##'
    ##' @param detailed Logical, indicating if detailed information
    ##'   should be returned
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

    ##' @description Enable an authentication backend in the vault
    ##'   server.
    ##'
    ##' @param type The type of authentication backend (e.g.,
    ##'   `userpass`, `github`)
    ##'
    ##' @param description Human-friendly description of the backend;
    ##'   will be returned by `$list()`
    ##'
    ##' @param local Specifies if the auth method is local only. Local
    ##'   auth methods are not replicated nor (if a secondary) removed
    ##'   by replication.
    ##'
    ##' @param path Specifies the path in which to enable the auth
    ##'     method. Defaults to be the same as `type`.
    enable = function(type, description = NULL, local = FALSE, path = NULL) {
      ## TODO: not passing in config here
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

    ##' @description Disable an active authentication backend.
    ##'
    ##' @param path The path of the authentication backend to disable.
    disable = function(path) {
      private$api_client$DELETE(paste0("/sys/auth/", path))
      invisible(NULL)
    }
  ))

##' Interact with vault's secret backends.
##'
##' @title Vault Secret Configuration
##' @name vault_client_secrets
##' @examples
##'
##' server <- vaultr::vault_test_server(if_disabled = message)
##' if (!is.null(server)) {
##'   client <- server$client()
##'
##'   # To remove the default version 1 kv store and replace with a
##'   # version 2 store:
##'   client$secrets$disable("/secret")
##'   client$secrets$enable("kv", "/secret", version = 2)
##'
##'   # cleanup
##'   server$kill()
##' }
vault_client_secrets <- R6::R6Class(
  "vault_client_secrets",
  inherit = vault_client_object,
  cloneable = FALSE,

  private = list(api_client = NULL),

  public = list(
    cubbyhole = NULL,
    kv1 = NULL,
    kv2 = NULL,
    transit = NULL,

    initialize = function(api_client) {
      super$initialize("Interact with secret engines")
      private$api_client <- api_client
      add_const_member(self, "cubbyhole",
                       vault_client_cubbyhole$new(api_client))
      add_const_member(self, "kv1",
                       vault_client_kv1$new(api_client, NULL))
      add_const_member(self, "kv2",
                       vault_client_kv2$new(api_client, "secret"))
      add_const_member(self, "transit",
                       vault_client_transit$new(api_client, "transit"))
    },

    ##' @description Disable a previously-enabled secret engine
    ##'
    ##' @param path Path of the secret engine
    disable = function(path) {
      if (!is_absolute_path(path)) {
        path <- paste0("/", path)
      }
      private$api_client$DELETE(paste0("/sys/mounts", path))
      invisible(NULL)
    },

    ##' @description Enable a secret backend in the vault server
    ##'
    ##' @param type The type of secret backend (e.g., `transit`, `kv`).
    ##'
    ##' @param description Human-friendly description of the backend;
    ##'   will be returned by `$list()`
    ##'
    ##' @param path Specifies the path in which to enable the auth
    ##'   method. Defaults to be the same as `type`.
    ##'
    ##' @param version Used only for the `kv` backend, where an integer
    ##'   is used to select between [vaultr::vault_client_kv1] and
    ##'   [vaultr::vault_client_kv2] engines.
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

    ##' @description List enabled secret engines
    ##'
    ##' @param detailed Logical, indicating if detailed output is
    ##'   wanted.
    list = function(detailed = FALSE) {
      if (detailed) {
        stop("Detailed secret information not supported")
      }
      dat <- private$api_client$GET("/sys/mounts")
      cols <- c("type", "accessor", "description")
      ret <- lapply(cols, function(v)
        vapply(dat$data, "[[", "", v, USE.NAMES = FALSE))
      names(ret) <- cols
      as.data.frame(c(list(path = names(dat$data)), ret),
                    stringsAsFactors = FALSE, check.names = FALSE)
    },

    ##' @description Move the path that a secret engine is mounted at
    ##'
    ##' @param from Original path
    ##'
    ##' @param to New path
    move = function(from, to) {
      assert_scalar_character(from)
      assert_scalar_character(to)
      body <- list(from = from, to = to)
      private$api_client$POST("/sys/remount", body = body)
      invisible(NULL)
    }
  ))

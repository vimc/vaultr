##' Interact with vault's LDAP authentication backend.  This backend
##' can be used to configure users based on their presence or group
##' membership in an LDAP server.  For more information, please see
##' the vault documentation
##' https://developer.hashicorp.com/vault/docs/auth/ldap
##'
##' @title Vault LDAP Authentication Configuration
##' @name vault_client_auth_ldap
##'
##' @examples
##' server <- vaultr::vault_test_server(if_disabled = message)
##' if (!is.null(server)) {
##'   root <- server$client()
##'
##'   # The ldap authentication backend is not enabled by default,
##'   # so we need to enable it first
##'   root$auth$enable("ldap")
##'
##'   # Considerable configuration is required to make this work. Here
##'   # we use the public server available at
##'   # https://www.forumsys.com/2022/05/10/online-ldap-test-server/
##'   root$auth$ldap$configure(
##'     url = "ldap://ldap.forumsys.com",
##'     binddn = "cn=read-only-admin,dc=example,dc=com",
##'     bindpass = "password",
##'     userdn = "dc=example,dc=com",
##'     userattr = "uid",
##'     groupdn = "dc=example,dc=com",
##'     groupattr = "ou",
##'     groupfilter = "(uniqueMember={{.UserDN}})")
##'
##'   # You can associate groups of users with policies:
##'   root$auth$ldap$write("scientists", "default")
##'
##'   # Create a new client and login with this user:
##'   newton <- vaultr::vault_client(
##'     addr = server$addr,
##'     login = "ldap",
##'     username = "newton",
##'     password = "password")
##'
##'   # (it is not recommended to login with the password like this as
##'   # it will end up in the command history, but in interactive use
##'   # you will be prompted securely for password)
##'
##'   # Isaac Newton has now logged in and has only "default" policies
##'   newton$auth$token$lookup_self()$policies
##'
##'   # (wheras our original root user has the "root" policy)
##'   root$auth$token$lookup_self()$policies
##' }
vault_client_auth_ldap <- R6::R6Class(
  "vault_client_auth_ldap",
  inherit = vault_client_object,
  cloneable = FALSE,

  private = list(
    api_client = NULL,
    mount = NULL
  ),

  public = list(
    ##' @description Create a `vault_client_auth_ldap` object. Not typically
    ##'   called by users.
    ##'
    ##' @param api_client A [vaultr::vault_api_client] object
    ##'
    ##' @param mount Mount point for the backend
    initialize = function(api_client, mount) {
      super$initialize("Interact and configure vault's LDAP support")
      assert_scalar_character(mount)
      private$mount <- sub("^/", "", mount)
      private$api_client <- api_client
    },

    ##' @description Set up a `vault_client_auth_ldap` object at a
    ##'   custom mount. For example, suppose you mounted the `ldap`
    ##'   authentication backend at `/ldap-dev` you might use `ldap <-
    ##'   vault$auth$ldap2$custom_mount("/ldap-dev")` - this pattern
    ##'   is repeated for other secret and authentication backends.
    ##'
    ##' @param mount String, indicating the path that the engine is mounted at.
    custom_mount = function(mount) {
      vault_client_auth_ldap$new(private$api_client, mount)
    },

    ##' @description Configures the connection parameters for
    ##'   LDAP-based authentication. Note that there are many options
    ##'   here and not all may be well supported. You are probably best
    ##'   to configure your vault-LDAP interaction elsewhere, and this
    ##'   method should be regarded as experimental and for testing
    ##'   purposes only.
    ##'
    ##' See the official docs
    ##'   (https://developer.hashicorp.com/vault/api-docs/auth/ldap,
    ##'   "Configure LDAP") for the list of accepted parameters here
    ##'   via the dots argument; these are passed through directly
    ##'   (with the exception of `url` which is the only required
    ##'   parameter and for which concatenation of multiple values is
    ##'   done for you.
    ##'
    ##' @param url The LDAP server to connect to. Examples:
    ##'   `ldap://ldap.myorg.com`,
    ##'   `ldaps://ldap.myorg.com:636`. Multiple URLs can be specified
    ##'   with a character vector, e.g. `c("ldap://ldap.myorg.com", ,
    ##'   "ldap://ldap2.myorg.com")`; these will be tried in-order.
    ##'
    ##' @param ... Additional arguments passed through with the body
    configure = function(url, ...) {
      path <- sprintf("/auth/%s/config", private$mount)
      assert_character(url)
      body <- list(url = paste(url, collapse = ","), ...)
      private$api_client$POST(path, body = drop_null(body))
      invisible(TRUE)
    },

    ##' @description Reads the connection parameters for LDAP-based
    ##'   authentication.
    configuration = function() {
      private$api_client$GET(sprintf("/auth/%s/config", private$mount))$data
    },

    ##' @description Create or update a policy
    ##'
    ##' @param name The name of the group (or user)
    ##'
    ##' @param policies A character vector of vault policies that this
    ##'   group (or user) will have for vault access.
    ##'
    ##' @param user Scalar logical - if `TRUE`, then `name` is
    ##'   interpreted as a *user* instead of a group.
    write = function(name, policies, user = FALSE) {
      type <- if (assert_scalar_logical(user)) "users" else "groups"
      assert_scalar_character(name)
      path <- sprintf("/auth/%s/%s/%s", private$mount, type, name)

      assert_character(policies)
      body <- list(policies = paste(policies, collapse = ","))

      private$api_client$POST(path, body = body)
      invisible(NULL)
    },

    ##' @description Write a mapping between a LDAP group or user and
    ##'   a set of vault policies.
    ##'
    ##' @param name The name of the group (or user)
    ##'
    ##' @param user Scalar logical - if `TRUE`, then `name` is
    ##'   interpreted as a *user* instead of a group.
    read = function(name, user = FALSE) {
      type <- if (assert_scalar_logical(user)) "users" else "groups"
      assert_scalar_character(name)
      path <- sprintf("/auth/%s/%s/%s", private$mount, type, name)
      ret <- private$api_client$GET(path)$data
      ret$policies <- list_to_character(ret$policies)
      ret
    },

    ##' @description List groups or users known to vault via LDAP
    ##'
    ##' @param user Scalar logical - if `TRUE`, then list users
    ##'   instead of groups.
    list = function(user = FALSE) {
      type <- if (assert_scalar_logical(user)) "users" else "groups"
      path <- sprintf("/auth/%s/%s", private$mount, type)
      tryCatch(
        list_to_character(private$api_client$LIST(path)$data$keys),
        vault_invalid_path = function(e) character(0))
    },

    ##' @description Delete a group or user (just the mapping to vault,
    ##'   no data on the LDAP server is modified).
    ##'
    ##' @param name The name of the group (or user)
    ##'
    ##' @param user Scalar logical - if `TRUE`, then `name` is
    ##'   interpreted as a *user* instead of a group.
    delete = function(name, user = FALSE) {
      type <- if (assert_scalar_logical(user)) "users" else "groups"
      assert_scalar_character(name)
      path <- sprintf("/auth/%s/%s/%s", private$mount, type, name)
      private$api_client$DELETE(path)$data
    },

    ##' @description Log into the vault using LDAP authentication.
    ##'   Normally you would not call this directly but instead use
    ##'   `$login` with `method = "ldap"` and proving the `username`
    ##'   and optionally the `password` argument.
    ##'   argument.  This function returns a vault token but does not
    ##'   set it as the client token.
    ##'
    ##' @param username Username to authenticate with
    ##'
    ##' @param password Password to authenticate with. If omitted or
    ##'   `NULL` and the session is interactive, the password will be
    ##'   prompted for.
    login = function(username, password) {
      data <- userpass_data(username, password)
      path <- sprintf("/auth/%s/login/%s", private$mount, username)
      body <- list(password = data$password)
      res <- private$api_client$POST(path, body = body,
                                     allow_missing_token = TRUE)
      res$auth
    }
  ))

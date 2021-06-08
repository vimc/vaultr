##' Interact with vault's username/password authentication backend.
##' This backend can be used to configure basic username+password
##' authentication, suitable for human users.  For more information,
##' please see the vault documentation
##' \url{https://www.vaultproject.io/docs/auth/userpass.html}
##'
##' @template vault_client_auth_userpass
##'
##' @title Vault Username/Password Authentication Configuration
##' @name vault_client_auth_userpass
##'
##' @examples
##' server <- vaultr::vault_test_server(if_disabled = message)
##' if (!is.null(server)) {
##'   root <- server$client()
##'
##'   # The userpass authentication backend is not enabled by default,
##'   # so we need to enable it first
##'   root$auth$enable("userpass")
##'
##'   # Then we can add users:
##'   root$auth$userpass$write("alice", "p4ssw0rd")
##'
##'   # Create a new client and login with this user:
##'   alice <- vaultr::vault_client(addr = server$addr)
##'   # it is not recommended to login with the password like this as
##'   # it will end up in the command history, but in interactive use
##'   # you will be prompted securely for password
##'   alice$login(method = "userpass",
##'               username = "alice", password = "p4ssw0rd")
##'   # Alice has now logged in and has only "default" policies
##'   alice$auth$token$lookup_self()$policies
##'
##'   # (wheras our original root user has the "root" policy)
##'   root$auth$token$lookup_self()$policies
##' }
vault_client_auth_userpass <- R6::R6Class(
  "vault_client_auth_userpass",
  inherit = vault_client_object,
  cloneable = FALSE,

  private = list(
    api_client = NULL,
    mount = NULL
  ),

  public = list(
    initialize = function(api_client, mount) {
      super$initialize("Interact and configure vault's userpass support")
      assert_scalar_character(mount)
      private$mount <- sub("^/", "", mount)
      private$api_client <- api_client
    },

    ##' @description Set up a `vault_client_auth_userpass` object at a
    ##'   custom mount.  For example, suppose you mounted the
    ##'   `userpass` authentication backend at `/userpass2` you might
    ##'   use `up <- vault$auth$userpass2$custom_mount("/userpass2")` -
    ##'   this pattern is repeated for other secret and authentication
    ##'   backends.
    ##'
    ##' @param mount String, indicating the path that the engine is mounted at.
    custom_mount = function(mount) {
      vault_client_auth_userpass$new(private$api_client, mount)
    },

    ##' @description Create or update a user.
    ##'
    ##' @param username Username for the user
    ##'
    ##' @param password Password for the user (required when creating a
    ##'   user only)
    ##'
    ##' @param policies Character vector of policies for the user
    ##'
    ##' @param ttl The lease duration which decides login expiration
    ##'
    ##' @param max_ttl Maximum duration after which login should expire
    ##'
    ##' @param bound_cidrs Character vector of CIDRs.  If set,
    ##'   restricts usage of the login and token to client IPs falling
    ##'   within the range of the specified CIDR(s).
    write = function(username, password = NULL, policies = NULL, ttl = NULL,
                   max_ttl = NULL, bound_cidrs = NULL) {
      username <- assert_scalar_character(username)
      body <- list(
        password = assert_scalar_character_or_null(password),
        policies = policies %&&%
          paste(assert_character(policies), collapse = ","),
        ttl = ttl %&&% assert_is_duration(ttl),
        max_ttl = max_ttl %&&% assert_is_duration(max_ttl),
        bound_cidrs = bound_cidrs %&&% I(assert_character(bound_cidrs)))
      path <- sprintf("/auth/%s/users/%s", private$mount, username)

      private$api_client$POST(path, body = drop_null(body))
      invisible(NULL)
    },

    ##' @description Reads the properties of an existing username.
    ##'
    ##' @param username Username to read
    read = function(username) {
      assert_scalar_character(username)
      path <- sprintf("/auth/%s/users/%s", private$mount, username)
      ret <- private$api_client$GET(path)$data
      ret$policies <- list_to_character(ret$policies)
      ret
    },

    ##' @description Delete a user
    ##'
    ##' @param username Username to delete
    delete = function(username) {
      assert_scalar_character(username)
      path <- sprintf("/auth/%s/users/%s", private$mount, username)
      private$api_client$DELETE(path)
      invisible(NULL)
    },

    ##' @description Update password for a user
    ##'
    ##' @param username Username for the user to update
    ##'
    ##' @param password New password for the user
    update_password = function(username, password) {
      assert_scalar_character(username)
      body <- list(password = assert_scalar_character(password))
      path <- sprintf("/auth/%s/users/%s/password", private$mount, username)

      private$api_client$POST(path, body = drop_null(body))
      invisible(NULL)
    },

    ##' @description Update vault policies for a user
    ##'
    ##' @param username Username for the user to update
    ##'
    ##' @param policies Character vector of policies for this user
    update_policies = function(username, policies) {
      assert_scalar_character(username)
      body <- list(policies = paste(assert_character(policies),
                                    collapse = ","))
      path <- sprintf("/auth/%s/users/%s/policies", private$mount, username)

      private$api_client$POST(path, body = drop_null(body))
      invisible(NULL)
    },

    ##' @description List users known to vault
    list = function() {
      path <- sprintf("/auth/%s/users", private$mount)
      tryCatch(
        list_to_character(private$api_client$LIST(path)$data$keys),
        vault_invalid_path = function(e) character(0))
    },

    ##' @description Log into the vault using username/password
    ##'   authentication.  Normally you would not call this directly
    ##'   but instead use `$login` with `method = "userpass"` and
    ##'   proving the `username` argument and optionally the `password`
    ##'   argument.  This function returns a vault token but does not
    ##'   set it as the client token.
    ##'
    ##' @param username Username to authenticate with
    ##'
    ##' @param password Password to authenticate with. If omitted or
    ##'   `NULL` and the session is interactive, the password will be
    ##'   prompted for.
    login = function(username, password = NULL) {
      data <- userpass_data(username, password)
      path <- sprintf("/auth/%s/login/%s", private$mount, username)
      body <- list(password = data$password)
      res <- private$api_client$POST(path, body = body,
                                     allow_missing_token = TRUE)
      res$auth
    }
  ))


## Needs to be a free function so that we can mock out the password
## read reliably
userpass_data <- function(username, password) {
  assert_scalar_character(username, "username")
  if (is.null(password)) {
    msg <- sprintf("Password for '%s': ", username)
    password <- read_password(msg)
  }
  assert_scalar_character(password, "password")
  list(username = username, password = password)
}

##' Interact with vault's username/password authentication backend.
##'
##' @template vault_client_auth_userpass
##'
##' @title Vault Username/Password Authentication Configuration
##' @name vault_client_auth_userpass
NULL


R6_vault_client_auth_userpass <- R6::R6Class(
  "vault_client_auth_userpass",

  private = list(
    api_client = NULL,
    mount = NULL
  ),

  public = list(
    initialize = function(api_client, mount) {
      assert_scalar_character(mount)
      private$mount <- sub("^/", "", mount)
      private$api_client <- api_client
    },

    format = function(brief = FALSE) {
      vault_client_format(self, brief, "userpass",
                          "Interact and configure vault's userpass support")
    },

    custom_mount = function(mount) {
      R6_vault_client_auth_userpass$new(private$api_client, mount)
    },

    write = function(username, password = NULL, policy = NULL, ttl = NULL,
                   max_ttl = NULL, bound_cidrs = NULL) {
      username = assert_scalar_character(username)
      body <- list(
        password = assert_scalar_character_or_null(password),
        policies = policy %&&% paste(assert_character(policy), collapse = ","),
        ttl = ttl %&&% assert_is_duration(ttl),
        max_ttl = max_ttl %&&% assert_is_duration(max_ttl),
        bound_cidrs = bound_cidrs %&&% I(assert_character(bound_cidrs)))
      path <- sprintf("/auth/%s/users/%s", private$mount, username)

      private$api_client$POST(path, body = drop_null(body))
      invisible(NULL)
    },

    read = function(username) {
      assert_scalar_character(username)
      path <- sprintf("/auth/%s/users/%s", private$mount, username)
      ret <- private$api_client$GET(path)$data
      ret$policies <- list_to_character(ret$policies)
      ret
    },

    delete = function(username) {
      assert_scalar_character(username)
      path <- sprintf("/auth/%s/users/%s", private$mount, username)
      private$api_client$DELETE(path)
      invisible(NULL)
    },

    update_password = function(username, password) {
      assert_scalar_character(username)
      body <- list(password = assert_scalar_character(password))
      path <- sprintf("/auth/%s/users/%s/password", private$mount, username)

      private$api_client$POST(path, body = drop_null(body))
      invisible(NULL)
    },

    update_policies = function(username, policy) {
      assert_scalar_character(username)
      body <- list(policies = paste(assert_character(policy), collapse = ","))
      path <- sprintf("/auth/%s/users/%s/policies", private$mount, username)

      private$api_client$POST(path, body = drop_null(body))
      invisible(NULL)
    },

    list = function() {
      path <- sprintf("/auth/%s/users", private$mount)
      tryCatch(
        list_to_character(private$api_client$LIST(path)$data$keys),
        vault_invalid_path = function(e) character(0))
    },

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

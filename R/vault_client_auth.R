R6_vault_client_auth_github <- R6::R6Class(
  "vault_client_auth_github",

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
      vault_client_format(self, brief, "github",
                          "Interact and configure vault's github support")
    },

    custom_mount = function(mount) {
      R6_vault_client_auth_github$new(private$api_client, mount)
    },

    configure = function(organization, base_url = NULL, ttl = NULL,
                         max_ttl = NULL) {
      path <- sprintf("/auth/%s/config", private$mount)
      assert_scalar_character(organization)
      body <- list(organization = organization,
                   base_url = base_url,
                   ttl = ttl,
                   max_ttl = max_ttl)
      private$api_client$POST(path, body = drop_null(body))
      invisible(TRUE)
    },

    configuration = function() {
      private$api_client$GET(sprintf("/auth/%s/config", private$mount))$data
    },

    write = function(team_name, policy, user = FALSE) {
      type <- if (assert_scalar_logical(user)) "users" else "teams"
      assert_scalar_character(team_name)
      path <- sprintf("/auth/%s/map/%s/%s", private$mount, type, team_name)

      assert_character(policy)
      body <- list(policies = paste(policy, collapse = ","))

      private$api_client$POST(path, body = body)
      invisible(NULL)
    },

    read = function(team_name) {
      type <- if (assert_scalar_logical(user)) "users" else "teams"
      assert_scalar_character(team_name)
      path <- sprintf("/auth/%s/map/%s/%s", private$mount, type, team_name)
      private$api_client$GET(path)$data
    },

    login = function(token = NULL) {
      path <- sprintf("/auth/%s/login", private$mount)
      body <- list(token = vault_auth_github_token(token))
      res <- private$api_client$POST(path, body = body,
                                     allow_missing_token = TRUE)
      res$auth
    }
  ))


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

    add = function(username, password, policy = NULL, ttl = NULL,
                   max_ttl = NULL, bound_cidrs = NULL) {
      username = assert_scalar_character(username)
      body <- list(
        password = assert_scalar_character(password),
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
      assert_scalar_character(username, "username")
      if (is.null(password)) {
        msg <- sprintf("Password for '%s': ", username)
        password <- read_password(msg)
      }
      assert_scalar_character(password, "password")

      path <- sprintf("/auth/%s/login/%s", private$mount, username)
      body <- list(password = password)
      res <- private$api_client$POST(path, body = body,
                                     allow_missing_token = TRUE)
      res$auth
    }
  ))

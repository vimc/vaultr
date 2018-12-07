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
      ## NOTE: previously I had used 'policies' here and that didn't
      ## work!  Where else is that used?
      body <- list(value = paste(policy, collapse = ","))

      private$api_client$POST(path, body = body)
      invisible(NULL)
    },

    read = function(team_name, user = FALSE) {
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

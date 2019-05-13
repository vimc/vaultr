##' Interact with vault's GitHub authentication backend.  For more
##' details, please see the vault documentation at
##' \url{https://www.vaultproject.io/docs/auth/github.html}
##'
##' @template vault_client_auth_github
##'
##' @title Vault GitHub Authentication Configuration
##' @name vault_client_auth_github
##'
##' @examples
##' server <- vaultr::vault_test_server(if_disabled = message)
##' if (!is.null(server)) {
##'   client <- server$client()
##'
##'   client$auth$enable("github")
##'   # To enable login for members of the organisation "vimc":
##'   client$auth$github$configure(organization = "vimc")
##'   # To map members of the "robots" team *within* that organisation
##'   # to the "defaut" policy:
##'   cl$auth$github$write("development", "default")
##'
##'   # Once configured like this, if we have a PAT for a member of
##'   # the "development" team saved as an environment variable
##'   # "VAULT_AUTH_GITHUB_TOKEN" then doing
##'   #
##'   #   vaultr::vault_client(addr = ..., login = "github")
##'   #
##'   # will contact GitHub to verify the user token and vault will
##'   # then issue a client token
##'
##'   # cleanup
##'   server$kill()
##' }
NULL


vault_client_auth_github <- R6::R6Class(
  "vault_client_auth_github",
  inherit = vault_client_object,
  cloneable = FALSE,

  private = list(
    api_client = NULL,
    mount = NULL
  ),

  public = list(
    initialize = function(api_client, mount) {
      super$initialize("Interact and configure vault's github support")
      assert_scalar_character(mount)
      private$mount <- sub("^/", "", mount)
      private$api_client <- api_client
    },

    custom_mount = function(mount) {
      vault_client_auth_github$new(private$api_client, mount)
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

    write = function(team_name, policies, user = FALSE) {
      type <- if (assert_scalar_logical(user)) "users" else "teams"
      assert_scalar_character(team_name)
      path <- sprintf("/auth/%s/map/%s/%s", private$mount, type, team_name)

      assert_character(policies)
      ## NOTE: previously I had used 'policies' here and that didn't
      ## work!  Where else is that used?
      body <- list(value = paste(policies, collapse = ","))

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


vault_auth_github_token <- function(token) {
  if (is.null(token)) {
    token <- Sys_getenv("VAULT_AUTH_GITHUB_TOKEN", NULL)
  }
  if (is.null(token)) {
    stop(
      "GitHub token was not found: perhaps set 'VAULT_AUTH_GITHUB_TOKEN'")
  }
  assert_scalar_character(token)
  token
}

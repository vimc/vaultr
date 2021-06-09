##' Interact with vault's GitHub authentication backend.  For more
##' details, please see the vault documentation at
##' https://www.vaultproject.io/docs/auth/github.html
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
##'   client$auth$github$write("development", "default")
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
vault_client_auth_github <- R6::R6Class(
  "vault_client_auth_github",
  inherit = vault_client_object,
  cloneable = FALSE,

  private = list(
    api_client = NULL,
    mount = NULL
  ),

  public = list(
    ##' @description Create a `vault_client_github` object. Not typically
    ##'   called by users.
    ##'
    ##' @param api_client A [vaultr::vault_api_client] object
    ##'
    ##' @param mount Mount point for the backend
    initialize = function(api_client, mount) {
      super$initialize("Interact and configure vault's github support")
      assert_scalar_character(mount)
      private$mount <- sub("^/", "", mount)
      private$api_client <- api_client
    },

    ##' @description Set up a `vault_client_auth_github` object at a
    ##'   custom mount.  For example, suppose you mounted the `github`
    ##'   authentication backend at `/github-myorg` you might use `gh
    ##'   <- vault$auth$github2$custom_mount("/github-myorg")` - this
    ##'   pattern is repeated for other secret and authentication
    ##'   backends.
    ##'
    ##' @param mount String, indicating the path that the engine is
    ##'   mounted at.
    custom_mount = function(mount) {
      vault_client_auth_github$new(private$api_client, mount)
    },

    ##' @description Configures the connection parameters for
    ##'   GitHub-based authentication.
    ##'
    ##' @param organization The organization users must be part of
    ##'   (note American spelling).
    ##'
    ##' @param base_url The API endpoint to
    ##'   use. Useful if you are running GitHub Enterprise or an
    ##'   API-compatible authentication server.
    ##'
    ##' @param ttl Duration after which authentication will be expired
    ##'
    ##' @param max_ttl Maximum duration after which authentication will
    ##'   be expired
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

    ##' @description Reads the connection parameters for GitHub-based
    ##'   authentication.
    configuration = function() {
      private$api_client$GET(sprintf("/auth/%s/config", private$mount))$data
    },

    ##' @description Write a mapping between a GitHub team or user and
    ##'   a set of vault policies.
    ##'
    ##' @param team_name String, with the GitHub team name
    ##'
    ##' @param policies A character vector of vault policies that this
    ##'   user or team will have for vault access if they match this
    ##'   team or user.
    ##'
    ##' @param user Scalar logical - if `TRUE`, then `team_name` is
    ##'   interpreted as a *user* instead.
    write = function(team_name, policies, user = FALSE) {
      type <- if (assert_scalar_logical(user)) "users" else "teams"
      assert_scalar_character(team_name)
      path <- sprintf("/auth/%s/map/%s/%s", private$mount, type, team_name)

      assert_character(policies)
      body <- list(value = paste(policies, collapse = ","))

      private$api_client$POST(path, body = body)
      invisible(NULL)
    },

    ##' @description Write a mapping between a GitHub team or user and
    ##'   a set of vault policies.
    ##'
    ##' @param team_name String, with the GitHub team name
    ##'
    ##' @param user Scalar logical - if `TRUE`, then `team_name` is
    ##'   interpreted as a *user* instead.
    read = function(team_name, user = FALSE) {
      type <- if (assert_scalar_logical(user)) "users" else "teams"
      assert_scalar_character(team_name)
      path <- sprintf("/auth/%s/map/%s/%s", private$mount, type, team_name)
      private$api_client$GET(path)$data
    },

    ##' @description Log into the vault using GitHub authentication.
    ##'   Normally you would not call this directly but instead use
    ##'   `$login` with `method = "github"` and proving the `token`
    ##'   argument.  This function returns a vault token but does not
    ##'   set it as the client token.
    ##'
    ##' @param token A GitHub token to authenticate with.
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

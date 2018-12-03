vault_login <- function(api_client, method, quiet, ...) {
  data <- drop_null(list(...))
  assert_named(data)
  vault_login_info(method)(api_client, data, quiet)
}


vault_login_info <- function(method) {
  vault_methods <- list(
    token = vault_token_token,
    github = vault_token_github,
    userpass = vault_login_userpass)
  ret <- vault_methods[[method]]
  if (is.null(ret)) {
    stop(sprintf("Authentication method '%s' not supported", method))
  }
  ret
}


## These functions all get client tokens in different ways - there are
## more of these - there should be a key/value one too.  I am not
## certain that any of these really need verification though aside
## from the plain token because everything else is going to go
## _through_ the vault anyway.  So perhaps we just check the first:
vault_token_token <- function(client, data, quiet) {
  token <- vault_arg(data$token, "VAULT_TOKEN")
  if (is.null(token)) {
    stop("token not found (check $VAULT_TOKEN environment variable)")
  }
  assert_scalar_character(token)
  if (!quiet) {
    message("Verifying token")
  }
  client$verify_token(token)
  token
}


vault_token_github <- function(client, data, quiet) {
  if (!quiet) {
    message("Authenticating using github...", appendLF = FALSE)
  }

  token <- vault_auth_github_token(data$token)
  res <- client$POST("/auth/github/login",
                     body = list(token = token),
                     allow_missing_token = TRUE)
  if (!quiet) {
    message(pretty_lease(res$auth$lease_duration))
  }

  res$auth$client_token
}


vault_login_userpass <- function(client, data, quiet) {
  assert_scalar_character(data$username, "username")
  if (is.null(data$password)) {
    msg <- sprintf("Password for '%s': ", data$username)
    data$password <- read_password(msg)
  }
  assert_scalar_character(data$password, "password")

  path <- paste0("/auth/userpass/login/", data$username)
  data <- list(password = data$password)
  res <- client$POST(path, body = data, allow_missing_token = TRUE)

  if (!quiet) {
    message(pretty_lease(res$auth$lease_duration))
  }

  res$auth$client_token
}

vault_env <- new.env(parent = new.env())
vault_env$tokens <- new.env(parent = new.env())
vault_env$login <- list(
  userpass = R6_vault_client_auth_userpass,
  github = R6_vault_client_auth_github)

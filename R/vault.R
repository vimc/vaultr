vault_addr <- function(addr) {
  addr <- addr %||%
    getOption("vault.addr",
              Sys.getenv("VAULT_ADDR", NA_character_))
  if (!is.character(addr) || length(addr) != 1L) {
    stop("invalid input for vault addr")
  }
  if (is.na(addr)) {
    stop("vault address not found")
  }
  if (!grepl("^https://.+", addr)) {
    stop("Expected an https url for vault addr")
  }
  addr
}

vault_auth_github_token <- function(token) {
  if (is.null(token)) {
    token <- Sys.getenv("VAULT_AUTH_GITHUB_TOKEN", NA_character_)
  }
  token
}

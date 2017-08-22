## Montagu options:
vault <- new.env(parent = emptyenv())

##' Authenticate to vault.  Currently the only authentication method
##' supported is github.
##'
##' You may need to set the following environment variables
##'
##' \itemize{
##'
##' \item{\code{VAULT_ADDR}: The address that your vault server is running on}
##'
##' \item{\code{VAULT_AUTH_GITHUB_TOKEN}: The github token that you
##' have set up to workwith vault}
##'
##' }
##'
##' @title Authenticate vault
##'
##' @param addr Optional vault address, to override the
##'   \code{VAULT_ADDR} environment variable.
##'
##' @param renew Re-authenticate, even if a token is already found
##'
##' @param quiet Don't print information on success
##'
##' @export
vault_auth <- function(addr = NULL, renew = FALSE, quiet = FALSE) {
  if (is.null(vault$addr)) {
    vault_server_options()
  }
  if (!is.null(vault$token) && !renew) {
    return(invisible(FALSE))
  }
  if (is.null(vault$addr)) {
    vault_server_options(addr)
  }

  dat <- switch(vault$auth,
                github = vault_auth_github(NULL, renew),
                stop("Unsupported auth method ", vault$auth))

  vault$token <- httr::add_headers("X-Vault-Token" = dat$auth$client_token)
  if (!quiet) {
    lease <- dat$auth$lease_duration
    message(sprintf("Authenticated using github, duration: %s s (%s)",
                    lease, prettyunits::pretty_sec(lease, TRUE)))
  }
  invisible(TRUE)
}

##' List keys in the vault
##' @title List keys
##'
##' @param path Vault path to list keys in (e.g., "secret")
##'
##' @param recursive List keys recursively?
##'
##' @export
vault_list <- function(path, recursive = FALSE) {
  assert_vault_auth()
  url <- sprintf("%s/%s?list=true", vault$url, path)
  res <- httr::GET(url, vault$token)
  httr::stop_for_status(res)
  dat <- response_to_json(res)
  ret <- file.path(path, list_to_character(dat$data$keys))
  if (recursive) {
    i <- grepl("/$", ret)
    if (any(i)) {
      new <- unlist(lapply(sub("/$", "", ret[i]), vault_list, TRUE),
                    use.names = FALSE)
      ret <- sort(c(ret[!i], new))
    }
  }
  ret
}

##' Read the values from a key
##'
##' @title Read values from a key
##' @param path Vault path to read
##' @param field Field to read (default returns all fields as a list)
##' @export
vault_read <- function(path, field = NULL) {
  assert_vault_auth()
  url <- sprintf("%s/%s", vault$url, path)
  res <- httr::GET(url, vault$token)
  httr::stop_for_status(res)
  dat <- response_to_json(res)
  if (is.null(field)) {
    dat$data
  } else {
    dat$data[[field]]
  }
}


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
  addr
}

vault_server_options <- function(addr = NULL) {
  api_version <- 1L
  vault$addr <- vault_addr(addr)
  vault$api_version <- 1L
  vault$url <- sprintf("%s/v%d", vault$addr, api_version)
  vault$auth <- "github"
}

vault_gh_token <- function(token) {
  if (is.null(token)) {
    token <- Sys.getenv("VAULT_AUTH_GITHUB_TOKEN", NA_character_)
  }
  token
}


vault_auth_github <- function(token = NULL, renew = FALSE) {
  url <- sprintf("%s/auth/github/login", vault$url)
  token <- vault_gh_token(token)
  res <- httr::POST(url, body = list(token = token), encode = "json")
  httr::stop_for_status(res)
  response_to_json(res)
}

assert_vault_auth <- function() {
  if (is.null(vault$token)) {
    stop("vault is not authenticated: use vault_auth()")
  }
}

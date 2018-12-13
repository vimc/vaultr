skip_if_no_vault_test_server <- function() {
  if (is.null(vault_test_server())) {
    testthat::skip("Test server not running")
  }
}

skip_if_no_vaultr_test_github_pat <- function() {
  if (has_vaultr_test_github_pat()) {
    return(invisible(TRUE))
  }
  skip("No access token set")
}

has_vaultr_test_github_pat <- function() {
  nzchar(vaultr_test_github_pat())
}

vaultr_test_github_pat <- function() {
  Sys.getenv("VAULTR_TEST_GITHUB_PAT", "")
}

get_error <- function(expr) {
  tryCatch(expr, error = identity)
}

has_internet <- function() {
  !is.null(suppressWarnings(utils::nsl("www.google.com")))
}

skip_if_no_internet <- function() {
  if (has_internet()) {
    return()
  }
  testthat::skip("no internet")
}


skip_if_vault_before <- function(version, server) {
  if (server$version() < version) {
    testthat::skip("This test requires vault >= %s", as.character(version))
  }
}


read_vault_env <- function() {
  txt <- readLines(".vault-env")
  tmp <- tempfile()
  on.exit(unlink(tmp))
  writeLines(sub("^export\\s+", "", readLines(".vault-env")), tmp)
  readRenviron(tmp)
}


## This wants refactoring because we'll move away from global state
## and instead use a version that starts and stops at each use.
test_vault_client <- function(..., login = TRUE) {
  read_vault_env()
  cl <- vault_client(...)
  if (login) {
    cl$login()
  }
  cl
}


## Enough interface to use for the token cache:
fake_api_client <- function(addr, success) {
  force(success)
  list(addr = addr,
       verify_token = function(token, quiet) list(success = success))
}

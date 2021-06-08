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
  skip_on_cran() # not worth it
  skip_on_os("windows")
  if (has_internet()) {
    return()
  }
  testthat::skip("no internet")
}


skip_if_vault_before <- function(required, server, api, description) {
  have <- server$version()
  if (have < required) {
    testthat::skip(
      vault_invalid_version(required, have, api, description)$message)
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


wait_kv_upgrade <- function(kv, p, n = 10, poll = 0.2) {
  for (i in seq_len(n)) {
    ok <- tryCatch({
      kv$list(p)
      TRUE
    }, error = function(e) FALSE)
    if (ok) {
      break
    }
    Sys.sleep(poll)
  }
}

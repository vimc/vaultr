skip_if_no_vault_test_server <- function() {
  if (is.null(vault_test_server())) {
    testthat::skip("Test server not running")
  }
}

skip_if_no_vault_auth_github_token <- function() {
  if (has_auth_github_token()) {
    return(invisible(TRUE))
  }
  skip("No access token set")
}

has_auth_github_token <- function() {
  nzchar(Sys.getenv("VAULT_AUTH_GITHUB_TOKEN"), "")
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

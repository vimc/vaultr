## We always want this run on travis, so set it manually.  The other
## option would be to do this in the .travis.yml 'env' section, but
## getting that working with the secure variables seems to be a bit of
## a trick.
if (identical(Sys.getenv("TRAVIS"), "true")) {
  Sys.setenv(VAULTR_TEST_SERVER_PORT= 18200)
}

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

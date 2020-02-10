context("vault: api client")

test_that("vault api client rejects unauthenticated attempts", {
  srv <- vault_test_server()
  cl <- srv$client(login = FALSE)
  api <- cl$api()

  expect_error(api$GET("/secret"),
               "Have not authenticated against vault")
  err <- tryCatch(api$GET("/secret", allow_missing_token = TRUE),
                  error = identity)
  expect_equal(err$code, 400)
})


test_that("error fallback", {
  ## this test depends on mocking httr internals, and that feels like
  ## an unwise thing to hope to have work over a medium term.  I'll
  ## probably move over to curl at some point.
  skip_on_cran()
  res <- list(status_code = 400L,
              headers = structure(list("content-type" = "text/plain"),
                                  class = c("insensitive", "list")),
              content = charToRaw("an error message"))
  class(res) <- "response"
  err <- tryCatch(vault_client_response(res), error = identity)
  expect_is(err, "vault_error")
  expect_is(err, "vault_invalid_request")
  expect_equal(err$code, 400L)
  expect_equal(err$message, "an error message")
})


test_that("token validation", {
  srv <- vault_test_server()
  cl <- srv$client(login = FALSE)
  api <- cl$api()

  expect_silent(api$verify_token(fake_token(), TRUE))
  expect_message(api$verify_token(fake_token(), FALSE), "Verifying token")

  expect_error(api$set_token(fake_token(), verify = TRUE, quiet = TRUE),
               "Token validation failed with error")
})


test_that("skip ssl validation", {
  skip_on_os("windows")
  srv <- vault_test_server(https = TRUE)

  cl1 <- vault_client(addr = srv$addr, tls_config = FALSE)
  cl1$login(token = srv$token, quiet = TRUE)
  expect_equal(cl1$list("/secret"), character(0))
})


test_that("vault_base_url", {
  withr::with_envvar(c(VAULT_ADDR = NA_character_), {
    expect_error(vault_addr(NULL), "vault address not found")
  })

  expect_error(vault_addr("file://foo"),
               "Expected an http or https url for vault addr")

  expect_equal(
    vault_base_url("https://vault.example.com", "/v1"),
    "https://vault.example.com/v1")
})

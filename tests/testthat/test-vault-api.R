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

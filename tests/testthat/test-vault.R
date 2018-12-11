context("vault")

test_that("api", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$write("/secret/a", list(key = 1))

  api <- cl$api()
  expect_is(api, "vault_api_client")
  ## Unauthenticated route:
  expect_equal(api$GET("/sys/seal-status"),
               cl$operator$seal_status())

  ## Authenticated route
  d <- api$GET("/secret/a")
  expect_equal(d$data$key, 1)
})

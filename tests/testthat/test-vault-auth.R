context("vault: auth")


test_that("auth", {
  srv <- vault_test_server()
  cl <- srv$client()
  expect_is(cl$auth, "vault_client_auth")
  d <- cl$auth$list()
  expect_equal(d$path, "token/")
  expect_equal(d$type, "token")
  expect_error(cl$auth$list(TRUE),
               "Detailed auth information not supported")
})

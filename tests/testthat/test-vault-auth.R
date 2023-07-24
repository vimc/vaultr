test_that("auth", {
  srv <- test_vault_test_server()
  cl <- srv$client()
  expect_s3_class(cl$auth, "vault_client_auth")
  d <- cl$auth$list()
  expect_equal(d$path, "token/")
  expect_equal(d$type, "token")
  expect_error(cl$auth$list(TRUE),
               "Detailed auth information not supported")
})


test_that("introspect methods", {
  srv <- test_vault_test_server()
  cl <- srv$client()

  expect_setequal(cl$auth$backends(),
                  c("token", "github", "userpass", "approle"))
})

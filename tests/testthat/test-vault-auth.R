context("vault: auth")


test_that("auth", {
  srv <- vault_test_server()
  cl <- srv$client()
  expect_is(cl$auth, "vault_client_auth")
  d <- cl$auth$list()
  expect_equal(d$path, "token/")
  expect_equal(d$type, "token")
})


test_that("basic auth", {
  srv <- vault_test_server()
  cl <- srv$client()
  cl$auth$enable("userpass", "user / password based auth")
  d <- cl$auth$list()
  expect_setequal(d$path, c("token/", "userpass/"))
  expect_setequal(d$type, c("token", "userpass"))

  cl2 <- srv$client(login = FALSE)
  expect_error(cl2$login(method = "userpass",
                         username = "rich",
                         password = "password"))

  cl$write("/auth/userpass/users/rich",
           list(password = "password", policies = "admins"))
  t <- cl2$login(method = "userpass",
                 username = "rich",
                 password = "password")
  expect_is(t, "character")
  expect_match(t, "^[-[:xdigit:]]+$")

  expect_equal(cl$list("auth/userpass/users"), "rich")
})

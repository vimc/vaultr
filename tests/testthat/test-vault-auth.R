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


test_that("userpass", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$auth$enable("userpass", "user / password based auth")
  expect_true("userpass" %in% cl$auth$list()$type)
  expect_equal(cl$auth$userpass$list(), character(0))

  cl$auth$userpass$add("rich", "pass")
  expect_equal(cl$auth$userpass$list(), "rich")

  d <- cl$auth$userpass$read("rich")
  expect_equal(d$policies, character(0))

  expect_error(cl$auth$userpass$login("rich", "wrong"))
  expect_silent(auth <- cl$auth$userpass$login("rich", "pass"))
  token <- auth$client_token
  expect_is(token, "character")
  expect_match(token, "^[-[:xdigit:]]+$")

  cl2 <- srv$client(login = FALSE)
  expect_error(cl2$login(token = token), NA)
})


test_that("userpass: login", {
  srv <- vault_test_server()
  cl <- srv$client()

  token <- cl$token$client()
  cl$token$capabilities_self("/sys")

  cl$auth$enable("userpass", "user / password based auth")
  cl$auth$userpass$add("rich", "pass", "default")

  cl2 <- srv$client(login = FALSE)
  cl2$login(method = "userpass",
            username = "rich", password = "pass")
})


test_that("userpass: update password", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$auth$enable("userpass", "user / password based auth")
  cl$auth$userpass$add("rich", "pass")
  cl$auth$userpass$update_password("rich", "word")

  expect_error(cl$auth$userpass$login("rich", "pass"))
  expect_silent(cl$auth$userpass$login("rich", "word"))
})


test_that("userpass: update policies", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$auth$enable("userpass", "user / password based auth")
  cl$auth$userpass$add("rich", "pass")
  expect_equal(cl$auth$userpass$read("rich")$policies, character(0))

  cl$auth$userpass$update_policies("rich", "root")
  expect_equal(cl$auth$userpass$read("rich")$policies, "root")
})


test_that("userpass: delete user", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$auth$enable("userpass", "user / password based auth")
  cl$auth$userpass$add("rich", "pass")
  cl$auth$userpass$delete("rich")
  expect_equal(cl$auth$userpass$list(), character(0))
  expect_error(cl$auth$userpass$login("rich", "pass"))
})


test_that("github auth", {
  skip("not automated yet")
  srv <- vault_test_server()
  cl <- srv$client()

  cl$auth$enable("github")
  cl$auth$github$configuration()

  cl$auth$github$configure(organization = "vimc")
  expect_equal(cl$auth$github$configuration()$organization, "vimc")

  auth <- cl$auth$github$login()
  token <- auth$client_token

  cl2 <- srv$client(login = FALSE)
  cl2$login(token = token)
})

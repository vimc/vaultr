context("vault: token")


test_that("capabilities-self", {
  srv <- vault_test_server()
  cl <- srv$client()
  expect_equal(cl$token$capabilities_self("/secret"),
               list("/secret" = "root"))
  expect_equal(cl$token$capabilities_self("secret"),
               list("secret" = "root"))
  expect_equal(cl$token$capabilities_self(c("secret", "/secret")),
               list("secret" = "root", "/secret" = "root"))
})


test_that("create token", {
  srv <- vault_test_server()
  cl <- srv$client()

  res <- cl$token$create(ttl = "1h")

  cl2 <- srv$client(login = FALSE)
  cl2$login(token = res)
})


test_that("lookup", {
  srv <- vault_test_server()
  cl <- srv$client()

  token <- cl$token$client()
  data <- cl$token$lookup(token)

  expect_equal(data$policies, "root")
})


test_that("revoke", {
  srv <- vault_test_server()
  cl <- srv$client()

  res <- cl$token$create(ttl = "1h")

  cl2 <- srv$client(login = FALSE)
  cl2$login(token = res)
  cl2$write("/secret/foo", list(a = 1))

  cl$token$revoke(res)
  expect_error(cl2$write("/secret/foo", list(a = 1)))
})


test_that("renew", {
  srv <- vault_test_server()
  cl <- srv$client()

  res1 <- cl$token$create(ttl = "1h")
  expect_true(cl$token$lookup(res1)$ttl <= 3600)

  res2 <- cl$token$renew(res1, "100h")
  expect_equal(res2$lease_duration, 360000)
  ttl <- cl$token$lookup(res1)$ttl
  expect_true(ttl > 3600)
})


test_that("access via auth", {
  srv <- vault_test_server()
  cl <- srv$client()
  expect_equal(cl$auth$token, cl$token)
})


test_that("login: incorrect args", {
  srv <- vault_test_server()
  cl <- srv$client(login = FALSE)
  token <- srv$token
  ## Can't detect these errors by string because they're R's
  expect_error(cl$login(method = "token"))
  expect_error(cl$login(t0ken = token, method = "token"))
  expect_error(cl$login(token = token, other = "thing", method = "token"))

  expect_error(cl$login(token = token, mount = "token2"),
               "method 'token' does not accept a custom mount")

  expect_message(cl$login(token = token), "Verifying")
  expect_equal(cl$token$lookup_self()$policies, "root")
})

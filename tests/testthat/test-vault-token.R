test_that("capabilities-self", {
  srv <- test_vault_test_server()
  cl <- srv$client()
  expect_equal(cl$token$capabilities_self("/secret"),
               list("/secret" = "root"))
  expect_equal(cl$token$capabilities_self("secret"),
               list("secret" = "root"))
  expect_equal(cl$token$capabilities_self(c("secret", "/secret")),
               list("secret" = "root", "/secret" = "root"))
})


test_that("capabilities-self", {
  srv <- test_vault_test_server()
  cl <- srv$client()

  expect_equal(
    cl$token$capabilities("sys", srv$token),
    list("sys" = "root"))
})


test_that("capabilities-accessor", {
  srv <- test_vault_test_server()
  cl <- srv$client()
  ac <- cl$token$lookup_self()$accessor

  expect_equal(
    cl$token$capabilities_accessor("sys", ac),
    list("sys" = "root"))
})


test_that("create token", {
  srv <- test_vault_test_server()
  cl <- srv$client()

  res <- cl$token$create(ttl = "1h")

  cl2 <- srv$client(login = FALSE)
  cl2$login(token = res, quiet = TRUE)
})


test_that("lookup", {
  srv <- test_vault_test_server()
  cl <- srv$client()

  token <- cl$token$client()
  data <- cl$token$lookup(token)

  expect_equal(data$policies, "root")
})


test_that("lookup-accessor", {
  srv <- test_vault_test_server()
  cl <- srv$client()
  ac <- cl$token$lookup_self()$accessor

  data <- cl$token$lookup_accessor(ac)
  expect_equal(data$policies, "root")
})


test_that("revoke", {
  srv <- test_vault_test_server()
  cl <- srv$client()

  res <- cl$token$create(ttl = "1h")

  cl2 <- srv$client(login = FALSE)
  cl2$login(token = res, quiet = TRUE)
  cl2$write("/secret/foo", list(a = 1))

  cl$token$revoke(res)
  expect_error(cl2$write("/secret/foo", list(a = 1)))
})


test_that("revoke-self", {
  srv <- test_vault_test_server()
  cl <- srv$client()

  token <- cl$token$create()
  cl2 <- srv$client(login = FALSE)
  cl2$login(token = token, quiet = TRUE)
  cl2$token$revoke_self()
  expect_error(cl2$write("/secret/foo", list(a = 1)))
})


test_that("revoke-accessor", {
  srv <- test_vault_test_server()
  cl <- srv$client()

  token <- cl$token$create()
  ac <- cl$token$lookup(token)$accessor

  cl2 <- srv$client(login = FALSE)
  cl2$login(token = token, quiet = TRUE)
  cl2$token$revoke_accessor(ac)
  expect_error(cl2$write("/secret/foo", list(a = 1)))
})


test_that("revoke-and-orphan", {
  srv <- test_vault_test_server()
  cl <- srv$client()

  res1 <- cl$token$create()

  cl2 <- srv$client(login = FALSE)
  cl2$login(token = res1, quiet = TRUE)
  cl2$write("/secret/foo", list(a = 1))

  res2 <- cl2$token$create()
  cl$token$revoke_and_orphan(res1)

  expect_error(cl$token$lookup(res1))
  data <- cl$token$lookup(res2)
  expect_true(data$orphan)
})


test_that("revoke-and-orphan", {
  srv <- test_vault_test_server()
  cl <- srv$client()
  expect_null(cl$token$tidy())
})


test_that("renew", {
  srv <- test_vault_test_server()
  cl <- srv$client()

  res1 <- cl$token$create(ttl = "1h")
  expect_true(cl$token$lookup(res1)$ttl <= 3600)

  res2 <- cl$token$renew(res1, "100h")
  expect_equal(res2$lease_duration, 360000)
  ttl <- cl$token$lookup(res1)$ttl
  expect_true(ttl > 3600)
})


test_that("renew-self", {
  srv <- test_vault_test_server()
  cl <- srv$client()

  token <- cl$token$create(ttl = "1h")
  cl2 <- srv$client(login = FALSE)
  cl2$login(token = token, quiet = TRUE)
  cl2$token$renew_self("100h")

  ttl <- cl$token$lookup(token)$ttl
  expect_true(ttl > 3600)
})


test_that("access via auth", {
  srv <- test_vault_test_server()
  cl <- srv$client()
  expect_equal(cl$auth$token, cl$token)
})


test_that("login: incorrect args", {
  srv <- test_vault_test_server()
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


test_that("token list", {
  srv <- test_vault_test_server()
  cl <- srv$client()
  expect_true(cl$token$lookup_self()$accessor %in% cl$token$list())
})


test_that("role write", {
  srv <- test_vault_test_server()
  cl <- srv$client()

  cl$policy$write("read-a", 'path "secret/a/*" {\n  policy = "read"}')
  cl$policy$write("read-b", 'path "secret/b/*" {\n  policy = "read"}')
  cl$token$role_write("nomad", allowed_policies = c("read-a", "read-b"))

  dat <- cl$token$role_read("nomad")
  expect_equal(dat$allowed_policies, c("read-a", "read-b"))
  expect_equal(dat$disallowed_policies, character())

  expect_equal(cl$token$role_list(), "nomad")
})


test_that("role delete", {
  srv <- test_vault_test_server()
  cl <- srv$client()

  cl$token$role_write("nomad")
  expect_equal(cl$token$role_list(), "nomad")
  cl$token$role_delete("nomad")
  expect_equal(cl$token$role_list(), character(0))
})


test_that("role list", {
  srv <- test_vault_test_server()
  cl <- srv$client()
  expect_equal(cl$token$role_list(), character(0))
})


test_that("login", {
  srv <- test_vault_test_server()
  cl <- srv$client()
  t <- fake_token()
  expect_error(cl$token$login(t),
               "Token login failed with error: .+")
})


test_that("find vault token", {
  t1 <- fake_token()
  t2 <- fake_token()

  withr::with_envvar(c(VAULT_TOKEN = NA_character_), {
    expect_equal(vault_auth_vault_token(t1), t1)
    expect_error(vault_auth_vault_token(NULL),
                 "Vault token was not found: perhaps set 'VAULT_TOKEN'")
    expect_error(vault_auth_vault_token(1), "'token' must be a character")
  })

  withr::with_envvar(c(VAULT_TOKEN = t2), {
    expect_equal(vault_auth_vault_token(t1), t1)
    expect_equal(vault_auth_vault_token(NULL), t2)
    expect_error(vault_auth_vault_token(1), "'token' must be a character")
  })
})

context("vault: auth: approle")

test_that("approle", {
  srv <- vault_test_server()
  cl <- srv$client()
  cl$auth$enable("approle")

  d <- cl$auth$list()
  expect_setequal(d$path, c("token/", "approle/"))
  expect_setequal(d$type, c("token", "approle"))

  ar <- cl$auth$approle
  expect_equal(ar$list(), character(0))
})


test_that("approle auth", {
  srv <- vault_test_server()
  cl <- srv$client()
  cl$auth$enable("approle")

  role_name <- "myrole"

  ar <- cl$auth$approle
  ar$role_add(role_name)
  expect_equal(ar$list(), role_name)

  d <- ar$role_read(role_name)
  expect_is(d, "list")
  expect_equal(d$policies, "default")

  role_id <- ar$read_role_id(role_name)
  expect_is(role_id, "character")
  expect_equal(length(role_id), 1L)

  secret <- ar$secret_id_generate(role_name)
  expect_setequal(names(secret), c("id", "accessor"))
  auth <- ar$login(role_id, secret$id)

  token <- auth$client_token
  expect_is(token, "character")

  cl2 <- srv$client(login = FALSE)
  expect_error(cl2$login(token = token), NA)
})


test_that("custom mount", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$auth$enable("approle", path = "approle2")
  ar <- cl$auth$approle$custom_mount("approle2")
  expect_is(ar, "vault_client_auth_approle")

  ar$role_add("server")
  expect_equal(ar$role_read("server")$policies, "default")
  expect_error(cl$auth$approle$role_read("server"))
})

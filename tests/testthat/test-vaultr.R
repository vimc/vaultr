context("vaultr")

test_that("unseal_multi", {
  on.exit(manager$unseal()) # in case things go wrong

  keys <- manager$keys
  cl <- test_client()

  expect_true(cl$sys_is_initialized())
  st <- cl$seal_status()
  expect_false(st$sealed)
  expect_false(cl$is_sealed())

  cl$seal()
  expect_true(cl$sys_is_initialized())
  expect_true(cl$seal_status()$sealed)

  expect_error(cl$read("/secret/foo"), "Vault is sealed")
  e <- get_error(cl$read("/secret/foo"))
  expect_is(e, "vault_down")

  res <- cl$unseal_multi(keys[1:2])
  expect_true(res$sealed)
  expect_equal(res$progress, 2)

  res <- cl$unseal_reset()
  expect_true(res$sealed)
  expect_true(cl$is_sealed())
  expect_equal(res$progress, 0)

  res <- cl$unseal_multi(keys)
  expect_false(res$sealed)
  expect_false(cl$is_sealed())
})

test_that("sys_leader_status", {
  st <- test_client()$sys_leader_status()
  expect_true("ha_enabled" %in% names(st))
})

test_that("generic: nonexistant keys", {
  cl <- test_client(vault_client_generic)
  expect_error(cl$read("foo"), "Expected path to start with '/secret/'",
               fixed = TRUE)
  expect_null(cl$read("/secret/foo"))
  expect_null(cl$delete("/secret/foo"))
  expect_null(cl$list("/secret/foo"))
})

test_that("generic: invalid data", {
  cl <- test_client(vault_client_generic)
  expect_error(cl$write("/secret/foo", NULL), "'data' must be named")
  expect_error(cl$write("/secret/foo", "a"), "'data' must be named")
})

test_that("generic: basic CRUD", {
  cl <- test_client(vault_client_generic)
  expect_null(cl$write("/secret/foo", list(value = "whatever")))
  expect_identical(cl$list("/secret/"), "/secret/foo")
  expect_identical(cl$read("/secret/foo"), list(value = "whatever"))
  expect_identical(cl$read("/secret/foo", "value"), "whatever")
  expect_null(cl$read("/secret/foo", "other"))
  expect_null(attr(cl$read("/secret/foo"), "info"))

  res <- cl$read("/secret/foo", info = TRUE)
  info <- attr(res, "info")
  expect_is(info$request_id, "character")
  expect_false(info$renewable)
  expect_is(info$lease_duration, "integer")

  cl$write("/secret/foo", list(a = 1, b = 2))
  expect_equal(cl$read("/secret/foo"), list(a = 1, b = 2))

  expect_null(cl$delete("/secret/foo"))
  expect_null(cl$read("/secret/foo"))
})

test_that("generic: recursive list", {
  cl <- test_client(vault_client_generic)

  paths <- c("/secret/dir1/dira/leaf1",
             "/secret/dir1/dira/leaf2",
             "/secret/dir1/dirb/leaf3",
             "/secret/dir1/dirb/leaf4",
             "/secret/dir2/leaf5",
             "/secret/dir2/leaf6",
             "/secret/leaf7")
  for (i in seq_along(paths)) {
    cl$write(paths[[i]], list(value = i))
  }

  expect_equal(cl$list("/secret"),
               c("/secret/dir1/", "/secret/dir2/", "/secret/leaf7"))
  expect_equal(cl$list("/secret", recursive = TRUE),
               paths)
  expect_equal(cl$list("/secret/leaf7", recursive = TRUE),
               "/secret/leaf7")
  expect_equal(cl$list("/secret/dir2", recursive = TRUE),
               c("/secret/dir2/leaf5", "/secret/dir2/leaf6"))
})

test_that("github auth", {
  skip_on_travis()
  skip_if_no_vault_auth_github_token()

  cl <- test_client()

  expect_false("github" %in% cl$list_auth_backends()$type)
  cl$enable_auth_backend("github")
  expect_true("github" %in% cl$list_auth_backends()$type)

  cl$config_auth_github_write("vimc")
  expect_equal(cl$config_auth_github_read()$organization, "vimc")

  cl2 <- test_client()
  cl2$token <- NULL

  expect_error(cl2$list("/secret"), "missing client token")
  cl2$auth("github")
  expect_error(cl2$list("/secret"), "permission denied")
  cl$config_auth_github_write_policy("development", "default")
  expect_equal(cl$config_auth_github_read_policy("development"), "default")

  rules <- c('path "secret/*" {',
             '  policy = "write"',
             '}')
  cl$policy_write("standard", paste(rules, collapse = "\n"))
  cl$config_auth_github_write_policy("development", "standard")
  expect_equal(cl$config_auth_github_read_policy("development"), "standard")
  expect_equal(cl$policy_read("standard"), paste(rules, collapse = "\n"))

  expect_error(cl2$list("/secret"), "permission denied")
  cl2$auth("github", renew = TRUE)

  expect_silent(cl2$list("/secret"))

  cl$disable_auth_backend("github")
  expect_error(cl2$list("/secret"), "permission denied")
})

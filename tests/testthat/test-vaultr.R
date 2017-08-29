context("vaultr")

test_that("addr", {
  withr::with_envvar(c("VAULT_ADDR" = NA_character_), {
    expect_error(vault_addr(NULL), "vault address not found")
    expect_error(vault_addr(NA_character_), "vault address not found")
  })
  expect_error(vault_addr(1), "invalid input for vault addr")
  expect_error(vault_addr(letters), "invalid input for vault addr")

  expect_error(vault_addr(""), "Expected an https url for vault addr")
  expect_error(vault_addr("http://yo"), "Expected an https url for vault addr")
})

test_that("auth_github_token", {
  withr::with_envvar(c("VAULT_AUTH_GITHUB_TOKEN" = NA_character_), {
    expect_equal(vault_auth_github_token(NULL), NA_character_)
    expect_equal(vault_auth_github_token("abcd"), "abcd")
  })
  withr::with_envvar(c("VAULT_AUTH_GITHUB_TOKEN" = "1234"), {
    expect_equal(vault_auth_github_token(NULL), "1234")
    expect_equal(vault_auth_github_token("abcd"), "abcd")
  })
})

test_that("unseal_multi", {
  skip_if_no_vault_test_server()
  on.exit(vault_test_server()$unseal()) # in case things go wrong

  keys <- vault_test_server()$keys
  cl <- vault_test_client()

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
  skip_if_no_vault_test_server()
  st <- vault_test_client()$sys_leader_status()
  expect_true("ha_enabled" %in% names(st))
})

test_that("generic: nonexistant keys", {
  skip_if_no_vault_test_server()
  cl <- vault_test_client(vault_client_generic)
  expect_error(cl$read("foo"), "Expected path to start with '/secret/'",
               fixed = TRUE)
  expect_null(cl$read("/secret/foo"))
  expect_null(cl$delete("/secret/foo"))
  expect_equal(cl$list("/secret/foo"), character(0))
})

test_that("generic: invalid data", {
  skip_if_no_vault_test_server()
  cl <- vault_test_client(vault_client_generic)
  expect_error(cl$write("/secret/foo", NULL), "'data' must be named")
  expect_error(cl$write("/secret/foo", "a"), "'data' must be named")
})

test_that("generic: basic CRUD", {
  skip_if_no_vault_test_server()
  cl <- vault_test_client(vault_client_generic)
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
  skip_if_no_vault_test_server()
  cl <- vault_test_client(vault_client_generic)

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
  on.exit({
    for (i in paths) {
      cl$delete(i)
    }
  })

  expect_equal(cl$list("/secret"),
               c("/secret/dir1/", "/secret/dir2/", "/secret/leaf7"))
  expect_equal(cl$list("/secret", recursive = TRUE),
               paths)
  expect_equal(cl$list("/secret/leaf7", recursive = TRUE), character(0))
  expect_equal(cl$list("/secret/dir2", recursive = TRUE),
               c("/secret/dir2/leaf5", "/secret/dir2/leaf6"))
})

test_that("generic: ttl", {
  skip_if_no_vault_test_server()
  cl <- vault_test_client(vault_client_generic)
  cl$write("/secret/foo", list(password = "yo"), ttl = "1h")
  res <- cl$read("/secret/foo")
  expect_equal(res$password, "yo")
  expect_equal(res$ttl, "1h")
  res <- cl$read("/secret/foo", info = TRUE)
  expect_equal(attr(res, "info")$lease_duration, 3600)
  cl$delete("/secret/foo")
})

test_that("generic: auth", {
  skip_if_no_vault_test_server()
  cl <- vault_test_client(vault_client_generic, auth = FALSE)
  expect_error(cl$read("/secret/foo"), "missing client token")
  expect_message(cl$auth("token", vault_test_server()$root_token),
                 "Authenticating using token")
  expect_null(cl$read("/secret/foo"))
})

test_that("backends", {
  skip_if_no_vault_test_server()
  cl <- vault_test_client()
  res <- cl$list_backends()
  expect_is(res, "data.frame")
  expect_true(all(c("name", "type", "local", "description", "config") %in%
                  names(res)))
})

test_that("policy", {
  skip_if_no_vault_test_server()
  cl <- vault_test_client()
  expect_true(setequal(cl$policy_list(), c("default", "root")))

  rules <- paste('path "secret/*" {',
                 '  policy = "read"',
                 '}',
                 sep = "\n")
  cl$policy_write("read-secret", rules)
  expect_true("read-secret" %in% cl$policy_list())
  expect_equal(cl$policy_read("read-secret"), rules)
  cl$policy_delete("read-secret")
  expect_false("read-secret" %in% cl$policy_list())
  expect_error(cl$policy_read("read-secret"), "Not Found")
})

test_that("insecure", {
  skip_if_no_vault_test_server()
  cl <- vault_client(auth = "token",
                     token = vault_test_server()$root_token,
                     quiet = TRUE,
                     verify = FALSE)
  expect_equal(cl$list("/secret"), character(0))
  expect_equal(cl$verify$options$ssl_verifypeer, 0)
})

test_that("auth: message", {
  skip_if_no_vault_test_server()
  cl <- vault_test_client(auth = FALSE)
  expect_message(cl$auth("token", vault_test_server()$root_token),
                 "Authenticating using token")
  expect_silent(cl$auth("token", vault_test_server()$root_token))
})

context("vault: slow tests")

test_that("github auth", {
  skip_if_no_vault_test_server()
  try_auth <- has_auth_github_token()

  cl <- vault_test_client()

  expect_false("github" %in% cl$list_auth_backends()$type)
  cl$enable_auth_backend("github")
  expect_true("github" %in% cl$list_auth_backends()$type)

  cl$config_auth_github_write("vimc")
  expect_equal(cl$config_auth_github_read()$organization, "vimc")

  cl2 <- vault_test_client(auth = FALSE)

  expect_error(cl2$list("/secret"), "missing client token")

  if (try_auth) {
    cl2$auth("github")
    expect_error(cl2$list("/secret"), "permission denied")
  }
  cl$config_auth_github_write_policy("robots", "default")
  expect_equal(cl$config_auth_github_read_policy("robots"), "default")

  rules <- c('path "secret/*" {',
             '  policy = "write"',
             '}')
  cl$policy_write("standard", paste(rules, collapse = "\n"))
  cl$config_auth_github_write_policy("robots", "standard")
  expect_equal(cl$config_auth_github_read_policy("robots"), "standard")
  expect_equal(cl$policy_read("standard"), paste(rules, collapse = "\n"))

  if (try_auth) {
    expect_error(cl2$list("/secret"), "permission denied")
    cl2$auth("github", renew = TRUE)
    expect_silent(cl2$list("/secret"))
  }

  cl$disable_auth_backend("github")

  if (try_auth) {
    expect_error(cl2$list("/secret"), "permission denied")
  }
})

context("new version")

## -- basic

test_that("read/write/list", {
  cl <- test_vault_client()

  path <- sprintf("/secret/%s/key1", rand_str(10))
  value <- rand_str(20)
  data <- list(value = value)

  cl$write(path, data)
  expect_equal(cl$read(path), data)
  expect_equal(cl$read(path, "value"), value)
  expect_null(cl$read(path, "other"), value)
  expect_equal(cl$list(dirname(path)), "key1")
  expect_equal(cl$list(dirname(path)), "key1")
  cl$delete(path)
})


test_that("status", {
  cl <- test_vault_client()
  status <- cl$status()

  expect_is(status, "list")
  expect_equal(status$progress, 0L)
})

## -- auth

test_that("auth", {
  cl <- test_vault_client()
  expect_is(cl$auth, "vault_client_auth")
  d <- cl$auth$list()
  expect_equal(d$path, "token/")
  expect_equal(d$type, "token")
})


test_that("basic auth", {
  cl <- test_vault_client()
  cl$auth$enable("userpass", "user / password based auth")
  d <- cl$auth$list()
  expect_setequal(d$path, c("token/", "userpass/"))
  expect_setequal(d$type, c("token", "userpass"))

  cl2 <- test_vault_client(login = FALSE)
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

  ## Cleanup:
  cl$delete("auth/userpass/users/rich")
  cl$auth$disable("userpass")
})


## --- secrets

test_that("enable/disable a secret engine", {
  cl <- test_vault_client()
  cl$secrets$enable("kv", version = 2)
  d <- cl$secrets$list()
  expect_true("kv/" %in% d$path)
  expect_equal(d$type["kv/" == d$path], "kv")
  cl$secrets$disable("kv")
  d <- cl$secrets$list()
  expect_false("kv/" %in% d$path)
})


## --- k/v

test_that("kv: basic set/get", {
  p <- rand_str(10)
  cl <- test_vault_client()
  cl$secrets$enable("kv", p, version = 2)
  on.exit(cl$secrets$disable(p))

  kv <- cl$kv$custom_mount(p)

  path <- sprintf("%s/a", p)
  data <- list(key = rand_str(10))
  meta <- kv$put(path, data)
  expect_is(meta, "list")
  expect_equal(meta$version, 1L)

  expect_equal(kv$get(path), data)
  expect_equal(kv$get(path, field = "key"), data$key)
  expect_equal(kv$get(path, metadata = TRUE),
               structure(data, metadata = meta))
})


test_that("kv: config", {
  p <- rand_str(10)
  cl <- test_vault_client()
  cl$secrets$enable("kv", p, version = 2)
  on.exit(cl$secrets$disable(p))
  config <- cl$kv$config(p)
  expect_is(config, "list")
  expect_equal(config$lease_duration, 0)
})

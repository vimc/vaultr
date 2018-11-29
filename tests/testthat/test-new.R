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


test_that("kv: versions", {
  p <- rand_str(10)
  cl <- test_vault_client()
  cl$secrets$enable("kv", p, version = 2)
  on.exit(cl$secrets$disable(p))

  cl <- test_vault_client()
  kv <- cl$kv$custom_mount(p)
  path <- sprintf("%s/a", p)

  kv$put(path, list(key = 1))
  kv$put(path, list(key = 2))

  expect_equal(kv$get(path, 1), list(key = 1))
  expect_equal(kv$get(path, 2), list(key = 2))
  m <- kv$metadata_get(path)
  expect_equal(length(m$versions), 2)
  expect_setequal(names(m$versions), c("1", "2"))
  expect_equal(m$current_version, 2L)
})


test_that("kv: delete latest version", {
  p <- rand_str(10)
  cl <- test_vault_client()
  cl$secrets$enable("kv", p, version = 2)
  on.exit(cl$secrets$disable(p))

  cl <- test_vault_client()
  kv <- cl$kv$custom_mount(p)
  path <- sprintf("%s/a", p)

  kv$put(path, list(key = 1))
  kv$put(path, list(key = 2))

  kv$delete(path)
  expect_equal(kv$get(path, version = 1), list(key = 1))
  expect_null(kv$get(path))

  m <- kv$metadata_get(path)
  expect_false(nzchar(m$versions[["1"]]$deletion_time))
  expect_true(nzchar(m$versions[["2"]]$deletion_time))
})


test_that("kv: delete multiple versions", {
  p <- rand_str(10)
  cl <- test_vault_client()
  cl$secrets$enable("kv", p, version = 2)
  on.exit(cl$secrets$disable(p))

  cl <- test_vault_client()
  kv <- cl$kv$custom_mount(p)
  path <- sprintf("%s/a", p)

  kv$put(path, list(key = 1))
  kv$put(path, list(key = 2))
  kv$put(path, list(key = 3))

  kv$delete(path, version = 1:2)

  m <- kv$metadata_get(path)
  expect_true(nzchar(m$versions[["1"]]$deletion_time))
  expect_true(nzchar(m$versions[["2"]]$deletion_time))
  expect_false(nzchar(m$versions[["3"]]$deletion_time))
})


test_that("kv: list", {
  p <- rand_str(10)
  cl <- test_vault_client()
  cl$secrets$enable("kv", p, version = 2)
  on.exit(cl$secrets$disable(p))

  cl <- test_vault_client()
  kv <- cl$kv$custom_mount(p)
  path <- sprintf("%s/a", p)
  kv$put(path, list(key = 1))

  expect_equal(kv$list(p), "a")
  expect_equal(kv$list(path), character(0))

  kv$put(sprintf("%s/b/c", p), list(key = 1))
  expect_setequal(kv$list(p), c("a", "b/"))
})


test_that("kv: undelete", {
  p <- rand_str(10)
  cl <- test_vault_client()
  cl$secrets$enable("kv", p, version = 2)
  on.exit(cl$secrets$disable(p))

  cl <- test_vault_client()
  kv <- cl$kv$custom_mount(p)
  path <- sprintf("%s/a", p)
  kv$put(path, list(key = 1))
  kv$put(path, list(key = 2))

  kv$delete(path, 1)
  expect_null(kv$get(path, 1))
  kv$undelete(path, 1)
  expect_equal(kv$get(path, 1), list(key = 1))
})


test_that("kv: destroy", {
  p <- rand_str(10)
  cl <- test_vault_client()
  cl$secrets$enable("kv", p, version = 2)
  on.exit(cl$secrets$disable(p))

  cl <- test_vault_client()
  kv <- cl$kv$custom_mount(p)
  path <- sprintf("%s/a", p)
  kv$put(path, list(key = 1))
  kv$put(path, list(key = 2))

  kv$destroy(path, 2)
  expect_null(kv$get(path))
  kv$undelete(path, 2)
  expect_null(kv$get(path))
})


test_that("kv: metadata put", {
  p <- rand_str(10)
  cl <- test_vault_client()
  cl$secrets$enable("kv", p, version = 2)
  on.exit(cl$secrets$disable(p))

  path <- sprintf("%s/a", p)
  kv <- cl$kv$custom_mount(p)
  kv$metadata_put(path, cas_required = TRUE, max_versions = 10)
  d <- kv$metadata_get(path)
  expect_true(d$cas_required)
  expect_equal(d$max_versions, 10)
  expect_equal(d$versions, setNames(list(), character()))
})


test_that("kv: metadata delete", {
  p <- rand_str(10)
  cl <- test_vault_client()
  cl$secrets$enable("kv", p, version = 2)
  on.exit(cl$secrets$disable(p))

  cl <- test_vault_client()
  kv <- cl$kv$custom_mount(p)
  path <- sprintf("%s/a", p)
  kv$put(path, list(key = 1))
  kv$put(path, list(key = 2))

  kv$metadata_delete(path)
  expect_null(kv$get(path))
  expect_null(kv$metadata_get(path))
})

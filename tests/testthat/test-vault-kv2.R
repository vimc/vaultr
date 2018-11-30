context("vault: kv2")

test_that("basic set/get", {
  srv <- vault_test_server()
  cl <- srv$client()

  p <- rand_str(10)
  cl$secrets$enable("kv", p, version = 2)

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


test_that("config", {
  srv <- vault_test_server()
  cl <- srv$client()

  p <- rand_str(10)
  cl$secrets$enable("kv", p, version = 2)
  config <- cl$kv$config(p)
  expect_is(config, "list")
  expect_equal(config$lease_duration, 0)
})


test_that("versions", {
  srv <- vault_test_server()
  cl <- srv$client()

  p <- rand_str(10)
  cl$secrets$enable("kv", p, version = 2)

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


test_that("delete latest version", {
  srv <- vault_test_server()
  cl <- srv$client()

  p <- rand_str(10)
  cl$secrets$enable("kv", p, version = 2)

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


test_that("delete multiple versions", {
  srv <- vault_test_server()
  cl <- srv$client()

  p <- rand_str(10)
  cl$secrets$enable("kv", p, version = 2)

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


test_that("list", {
  srv <- vault_test_server()
  cl <- srv$client()

  p <- rand_str(10)
  cl$secrets$enable("kv", p, version = 2)

  kv <- cl$kv$custom_mount(p)
  path <- sprintf("%s/a", p)
  kv$put(path, list(key = 1))

  expect_equal(kv$list(p), "a")
  expect_equal(kv$list(path), character(0))

  kv$put(sprintf("%s/b/c", p), list(key = 1))
  expect_setequal(kv$list(p), c("a", "b/"))
})


test_that("undelete", {
  srv <- vault_test_server()
  cl <- srv$client()

  p <- rand_str(10)
  cl$secrets$enable("kv", p, version = 2)

  kv <- cl$kv$custom_mount(p)
  path <- sprintf("%s/a", p)
  kv$put(path, list(key = 1))
  kv$put(path, list(key = 2))

  kv$delete(path, 1)
  expect_null(kv$get(path, 1))
  kv$undelete(path, 1)
  expect_equal(kv$get(path, 1), list(key = 1))
})


test_that("destroy", {
  srv <- vault_test_server()
  cl <- srv$client()

  p <- rand_str(10)
  cl$secrets$enable("kv", p, version = 2)

  kv <- cl$kv$custom_mount(p)
  path <- sprintf("%s/a", p)
  kv$put(path, list(key = 1))
  kv$put(path, list(key = 2))

  kv$destroy(path, 2)
  expect_null(kv$get(path))
  kv$undelete(path, 2)
  expect_null(kv$get(path))
})


test_that("metadata put", {
  srv <- vault_test_server()
  cl <- srv$client()

  p <- rand_str(10)
  cl$secrets$enable("kv", p, version = 2)

  path <- sprintf("%s/a", p)
  kv <- cl$kv$custom_mount(p)
  kv$metadata_put(path, cas_required = TRUE, max_versions = 10)
  d <- kv$metadata_get(path)
  expect_true(d$cas_required)
  expect_equal(d$max_versions, 10)
  expect_equal(d$versions, setNames(list(), character()))
})


test_that("metadata delete", {
  srv <- vault_test_server()
  cl <- srv$client()

  p <- rand_str(10)
  cl$secrets$enable("kv", p, version = 2)

  kv <- cl$kv$custom_mount(p)
  path <- sprintf("%s/a", p)
  kv$put(path, list(key = 1))
  kv$put(path, list(key = 2))

  kv$metadata_delete(path)
  expect_null(kv$get(path))
  expect_null(kv$metadata_get(path))
})

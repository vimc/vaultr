context("vault: kv2")

test_that("basic set/get", {
  srv <- vault_test_server()
  cl <- srv$client()

  p <- rand_str(10)
  cl$secrets$enable("kv", p, version = 2)

  kv <- cl$secrets$kv2$custom_mount(p)
  wait_kv_upgrade(kv, p)

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
  config <- cl$secrets$kv2$config(p)
  expect_is(config, "list")
  expect_equal(config$cas_required, FALSE)
  expect_equal(config$max_versions, 0)
})


test_that("versions", {
  srv <- vault_test_server()
  cl <- srv$client()

  p <- rand_str(10)
  cl$secrets$enable("kv", p, version = 2)

  kv <- cl$secrets$kv2$custom_mount(p)
  wait_kv_upgrade(kv, p)

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

  kv <- cl$secrets$kv2$custom_mount(p)
  wait_kv_upgrade(kv, p)

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

  kv <- cl$secrets$kv2$custom_mount(p)
  wait_kv_upgrade(kv, p)

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

  kv <- cl$secrets$kv2$custom_mount(p)
  wait_kv_upgrade(kv, p)

  path <- sprintf("%s/a", p)
  kv$put(path, list(key = 1))

  expect_equal(kv$list(p), "a")
  expect_equal(kv$list(p, TRUE), file.path(p, "a"))

  expect_equal(kv$list(path), character(0))

  kv$put(sprintf("%s/b/c", p), list(key = 1))
  expect_setequal(kv$list(p), c("a", "b/"))
})


test_that("undelete", {
  srv <- vault_test_server()
  cl <- srv$client()

  p <- rand_str(10)
  cl$secrets$enable("kv", p, version = 2)

  kv <- cl$secrets$kv2$custom_mount(p)
  wait_kv_upgrade(kv, p)

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

  kv <- cl$secrets$kv2$custom_mount(p)
  wait_kv_upgrade(kv, p)

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
  kv <- cl$secrets$kv2$custom_mount(p)
  wait_kv_upgrade(kv, p)

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

  kv <- cl$secrets$kv2$custom_mount(p)
  wait_kv_upgrade(kv, p)

  path <- sprintf("%s/a", p)
  kv$put(path, list(key = 1))
  kv$put(path, list(key = 2))

  kv$metadata_delete(path)
  expect_null(kv$get(path))
  expect_null(kv$metadata_get(path))
})


test_that("mount validation", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$secrets$enable("kv", "secret2", version = 2)
  kv <- cl$secrets$kv2$custom_mount("secret2")
  wait_kv_upgrade(kv, p)

  expect_error(
    kv$list("/secret"),
    "Invalid mount given for this path - expected 'secret2'")
  expect_error(
    kv$put("/secret2", list(a = 1)),
    "Invalid path")
})


test_that("put+cas", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$secrets$enable("kv", "secret2", version = 2)
  kv <- cl$secrets$kv2$custom_mount("secret2")
  wait_kv_upgrade(kv, p)

  d <- kv$put("secret2/a", list(a = 1))
  expect_error(kv$put("secret2/a", list(a = 2), cas = 2))
  expect_equal(kv$get("secret2/a", field = "a"), 1)
  expect_silent(kv$put("secret2/a", list(a = 2), cas = 1))
  expect_equal(kv$get("secret2/a", field = "a"), 2)
})

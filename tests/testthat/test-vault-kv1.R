context("vault: kv")


test_that("basic write/read", {
  srv <- vault_test_server()
  cl <- srv$client()

  data <- list(key = rand_str(10))
  path <- "secret/a"
  cl$write(path, data)

  expect_equal(cl$read(path), data)
  expect_equal(cl$read(path, "key"), data$key)
  res <- cl$read(path, metadata = TRUE)
  expect_is(attr(res, "metadata"), "list")
})


test_that("read non-existant data", {
  srv <- vault_test_server()
  cl <- srv$client()

  expect_null(cl$read("secret/missing"))
  expect_null(cl$read("secret/missing", metadata = TRUE))
  expect_null(cl$read("secret/missing", field = "field"))

  cl$write("secret/a", list(key = 1))
  expect_null(cl$read("secret/a", field = "field"))
})


test_that("delete data", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$write("secret/a", list(key = 1))
  expect_equal(cl$read("secret/a", "key"), 1)
  cl$delete("secret/a")
  expect_null(cl$read("secret/a", "key"))
})


test_that("list", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$write("secret/a", list(key = 1))
  cl$write("secret/b/c", list(key = 2))
  cl$write("secret/b/d/e", list(key = 2))

  expect_setequal(cl$list("secret"), c("a", "b/"))
  expect_setequal(cl$list("secret", TRUE), c("secret/a", "secret/b/"))
  expect_setequal(cl$list("secret/b"), c("c", "d/"))
  expect_setequal(cl$list("secret/b", TRUE), c("secret/b/c", "secret/b/d/"))
})


test_that("custom mount", {
  srv <- vault_test_server()
  cl <- srv$client()

  mount <- "/secret1"

  cl$secrets$enable("kv", mount, "", 1L)
  kv <- cl$kv1$custom_mount(mount)

  kv$write("/secret1/a", list(key = 1))
  kv$read("/secret1/a")

  expect_error(
    kv$read("/secret/a"),
    "Invalid mount given for this path - expected 'secret1'")
})

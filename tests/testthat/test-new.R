context("new version")

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

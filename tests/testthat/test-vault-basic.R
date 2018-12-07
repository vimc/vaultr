context("vault: basic")


test_that("read/write/list", {
  srv <- vault_test_server()
  cl <- srv$client()

  path <- sprintf("/secret/%s/key1", rand_str(10))
  value <- rand_str(20)
  data <- list(value = value)

  cl$write(path, data)
  expect_equal(cl$read(path), data)
  expect_equal(cl$read(path, "value"), value)
  expect_null(cl$read(path, "other"), value)
  expect_equal(cl$list(dirname(path)), "key1")
  expect_equal(cl$list(dirname(path)), "key1")
})


test_that("status", {
  srv <- vault_test_server()
  cl <- srv$client()
  status <- cl$status()

  expect_is(status, "list")
  expect_equal(status$progress, 0L)
})


test_that("re-login", {
  srv <- vault_test_server()
  cl <- srv$client()
  expect_null(cl$login(method = "impossible"))
  expect_error(cl$login(method = "impossible", renew = TRUE),
               "Unknown login method 'impossible' - must be one of")
})

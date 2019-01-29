context("vault: cubbyhole")

test_that("basic set/get/list/del", {
  srv <- vault_test_server()
  cl <- srv$client()

  expect_equal(cl$cubbyhole$list("/cubbyhole"), character(0))

  p <- "cubbyhole/mysecret"
  cl$cubbyhole$write(p, list(a = "data"))
  expect_equal(cl$cubbyhole$read(p), list(a = "data"))
  expect_equal(cl$cubbyhole$read(p, "a"), "data")
  expect_null(cl$cubbyhole$read(p, "b"))
  d <- cl$cubbyhole$read(p, metadata = TRUE)
  expect_true("metadata" %in% names(attributes(d)))

  expect_null(cl$cubbyhole$read("/cubbyhole/other"))

  expect_equal(cl$list("/cubbyhole"), "mysecret")
  expect_equal(cl$list("/cubbyhole", full_names = TRUE), p)

  cl$delete(p)
  expect_equal(cl$list("/cubbyhole"), character(0))
  expect_silent(cl$delete(p))
})


test_that("custom mount disabled", {
  srv <- vault_test_server()
  cl <- srv$client()
  expect_error(cl$cubbyhole$custom_mount("elsewhere"),
               "The cubbyhole secret engine cannot be moved")
})

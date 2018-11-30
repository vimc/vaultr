context("vault: secrets")


test_that("enable/disable a secret engine", {
  srv <- vault_test_server()
  cl <- srv$client()
  cl$secrets$enable("kv", version = 2)
  d <- cl$secrets$list()
  expect_true("kv/" %in% d$path)
  expect_equal(d$type["kv/" == d$path], "kv")
  cl$secrets$disable("kv")
  d <- cl$secrets$list()
  expect_false("kv/" %in% d$path)
})


test_that("move a secret engine", {
  srv <- vault_test_server()
  cl <- srv$client()
  p1 <- rand_str(10)
  p2 <- rand_str(10)
  cl$secrets$enable("kv", p1, version = 2)
  cl$secrets$move(p1, p2)
  d <- cl$secrets$list()
  cl$secrets$disable(p2)
  expect_true(paste0(p2, "/") %in% d$path)
  expect_false(paste0(p1, "/") %in% d$path)
})

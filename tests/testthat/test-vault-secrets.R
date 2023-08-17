test_that("secrets", {
  srv <- test_vault_test_server()
  cl <- srv$client()
  expect_s3_class(cl$secrets, "vault_client_secrets")
  d <- cl$secrets$list()
  expect_s3_class(d, "data.frame")
  expect_true("secret/" %in% d$path)
  expect_true("kv" %in% d$type)
  expect_error(cl$secrets$list(TRUE),
               "Detailed secret information not supported")
})


test_that("enable/disable a secret engine", {
  srv <- test_vault_test_server()
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
  srv <- test_vault_test_server()
  cl <- srv$client()
  p1 <- "oldpath"
  p2 <- "newpath"
  cl$secrets$enable("kv", p1, version = 2)
  cl$secrets$move(p1, p2)
  d <- cl$secrets$list()
  cl$secrets$disable(p2)
  expect_true(paste0(p2, "/") %in% d$path)
  expect_false(paste0(p1, "/") %in% d$path)
})

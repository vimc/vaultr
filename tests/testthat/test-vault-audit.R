test_that("audit", {
  srv <- vault_test_server()
  cl <- srv$client()

  d <- cl$audit$list()
  expect_equal(d, data_frame(path = character(),
                             type = character(),
                             description = character()))
})


test_that("enable/disable", {
  srv <- vault_test_server()
  cl <- srv$client()

  path <- tempfile()
  options <- list(file_path = path)
  description <- "a file audit device"
  cl$audit$enable("file", description, options = options)
  d <- cl$audit$list()
  expect_equal(d, data_frame(path = "file/", type = "file",
                             description = description))

  cl$audit$disable("file")
  d <- cl$audit$list()
  expect_equal(d, data_frame(path = character(),
                             type = character(),
                             description = character()))
})


test_that("calculate hash", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$audit$enable("file", options = list(file_path = tempfile()))
  res <- cl$audit$hash("foo", "file")
  ## TODO: this is as far as the python tests push things - the vault
  ## docs are a bit vague on how one can use the audit logs really.
  expect_match(res, "^hmac-sha256:")
})

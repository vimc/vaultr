context("vault: cubbyhole")

test_that("basic set/get/list/del", {
  srv <- vault_test_server()
  cl <- srv$client()

  expect_equal(cl$secrets$cubbyhole$list("/cubbyhole"), character(0))

  p <- "cubbyhole/mysecret"
  cl$secrets$cubbyhole$write(p, list(a = "data"))
  expect_equal(cl$secrets$cubbyhole$read(p), list(a = "data"))
  expect_equal(cl$secrets$cubbyhole$read(p, "a"), "data")
  expect_null(cl$secrets$cubbyhole$read(p, "b"))
  d <- cl$secrets$cubbyhole$read(p, metadata = TRUE)
  expect_true("metadata" %in% names(attributes(d)))

  expect_null(cl$secrets$cubbyhole$read("/cubbyhole/other"))

  expect_equal(cl$list("/cubbyhole"), "mysecret")
  expect_equal(cl$list("/cubbyhole", full_names = TRUE), p)

  cl$delete(p)
  expect_equal(cl$list("/cubbyhole"), character(0))
  expect_silent(cl$delete(p))
})


test_that("custom mount disabled", {
  srv <- vault_test_server()
  cl <- srv$client()
  expect_error(cl$secrets$cubbyhole$custom_mount("elsewhere"),
               "The cubbyhole secret engine cannot be moved")
})


## https://learn.hashicorp.com/vault/secrets-management/sm-cubbyhole
test_that("response wrapping example", {
  srv <- vault_test_server()
  cl <- srv$client()

  ## create an apps policy - I have mucked this up
  cl$policy$write("apps", 'path "secret/dev/*" {\n  policy = "read"}')
  cl$write("secret/dev/mysecret", list(a = 1))

  token <- cl$token$create(policies = "apps", wrap_ttl = "1h")

  cl_app <- srv$client(login = FALSE)
  info <- cl_app$wrap_lookup(token)

  response <- cl_app$unwrap(token)
  cl_app$login(method = "token", token = response$auth$client_token)
  expect_equal(cl_app$read("/secret/dev/mysecret"),
               list(a = 1))

  ## Can't look up the token now
  expect_error(cl_app$wrap_lookup(token))
})

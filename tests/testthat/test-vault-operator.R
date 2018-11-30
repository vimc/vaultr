context("vault: operator")


test_that("rekey", {
  srv <- vault_test_server()
  cl <- srv$client()

  ans <- cl$operator$rekey_start(5, 3)
  expect_is(ans$nonce, "character")
  expect_true(ans$started)
  expect_equal(ans$progress, 0)
  expect_equal(ans$required, 1)

  res <- cl$operator$rekey_submit(srv$keys[[1]], ans$nonce)
  expect_is(res$keys, "character")
  expect_is(res$keys_base64, "character")
  expect_equal(length(res$keys), 5)
  expect_equal(length(res$keys_base64), 5)

  ## and again!
  ans <- cl$operator$rekey_start(5, 3)
  v <- c("started", "progress", "required")
  expect_equal(
    cl$operator$rekey_submit(res$keys_base64[[1]], ans$nonce)[v],
    list(started = TRUE, progress = 1, required = 3))
  expect_equal(
    cl$operator$rekey_submit(res$keys_base64[[2]], ans$nonce)[v],
    list(started = TRUE, progress = 2, required = 3))
  res <- cl$operator$rekey_submit(res$keys_base64[[3]], ans$nonce)
  expect_true(res$complete)
  expect_is(res$keys, "character")
  expect_is(res$keys_base64, "character")
  expect_equal(length(res$keys), 5)
  expect_equal(length(res$keys_base64), 5)
})


test_that("cancel rekey", {
  srv <- vault_test_server()
  cl <- srv$client()

  ans <- cl$operator$rekey_start(5, 3)
  expect_equal(cl$operator$rekey_status(), ans)

  expect_null(cl$operator$rekey_cancel())
  expect_null(cl$operator$rekey_cancel())

  ans <- cl$operator$rekey_status()
  expect_false(ans$started)
})

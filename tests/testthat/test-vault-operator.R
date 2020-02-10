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


test_that("init", {
  skip_on_os("windows")
  srv <- vault_test_server(https = TRUE, init = FALSE)
  cl <- srv$client(login = FALSE)

  dat <- cl$operator$init(5, 3)
  expect_is(dat$keys, "character")
  expect_is(dat$keys_base64, "character")
  expect_equal(length(dat$keys), 5)
  expect_equal(length(dat$keys_base64), 5)

  v <- c("sealed", "progress")
  expect_equal(cl$operator$unseal(dat$keys[[1]])[v],
               list(sealed = TRUE, progress = 1L))
  expect_equal(cl$operator$unseal(dat$keys[[2]])[v],
               list(sealed = TRUE, progress = 2L))
  expect_equal(cl$operator$unseal(dat$keys[[3]])[v],
               list(sealed = FALSE, progress = 0L))
})


test_that("seal", {
  srv <- vault_test_server()
  cl <- srv$client()

  expect_false(cl$operator$seal_status()$sealed)
  cl$operator$seal()
  expect_true(cl$operator$seal_status()$sealed)
})


test_that("rotate", {
  srv <- vault_test_server()
  cl <- srv$client()

  d1 <- cl$operator$key_status()
  expect_null(cl$operator$rotate())
  d2 <- cl$operator$key_status()

  expect_equal(d1$term, 1)
  expect_equal(d2$term, 2)
})


test_that("leader status", {
  srv <- vault_test_server()
  cl <- srv$client()

  d <- cl$operator$leader_status()
  expect_false(d$ha_enabled)
})

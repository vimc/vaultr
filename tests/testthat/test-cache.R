test_that("cache", {
  cache <- token_cache$new()
  expect_s3_class(cache, "token_cache")
  expect_s3_class(vault_env$cache, "token_cache")
})


## integration tests:
test_that("invalidation is handled gracefully", {
  srv <- test_vault_test_server()
  cl <- srv$client()
  vault_env$cache$clear()
  cl$auth$enable("userpass", "user / password based auth")
  cl$auth$userpass$write("rich", "pass")

  cl2 <- srv$client(login = FALSE)
  cl2$login(username = "rich", password = "pass", method = "userpass",
            quiet = TRUE)

  expect_equal(vault_env$cache$list(), cl$api()$addr)
  expect_equal(vault_env$cache$get(cl$api()), cl2$api()$token)

  cl3 <- srv$client(login = FALSE)
  cl3$login(username = "rich", password = "pass", method = "userpass",
            quiet = TRUE)
  expect_equal(cl3$api()$token, cl2$api()$token)
  expect_false(cl3$api()$token == cl$api()$token)

  ## Then invalidate our token:
  cl2$token$revoke_self()
  expect_null(vault_env$cache$get(cl$api()))

  ## Next login gets fresh token:
  cl4 <- srv$client(login = FALSE)
  cl4$login(username = "rich", password = "pass", method = "userpass",
            quiet = TRUE)
  expect_false(cl4$api()$token == cl$api()$token)
  expect_false(cl4$api()$token == cl2$api()$token)
})


test_that("cache behaviour", {
  cache <- token_cache$new()
  cl <- fake_api_client("addr", TRUE)
  t <- fake_token()

  ## empty
  expect_null(cache$get(cl))
  expect_equal(cache$list(), character())

  cache$set(cl, t, FALSE)

  expect_null(cache$get(cl))
  expect_equal(cache$list(), character())

  cache$set(cl, t, TRUE)
  expect_equal(cache$get(cl), t)
  expect_equal(cache$list(), cl$addr)

  expect_null(cache$get(cl, FALSE))

  ## A failed lookup invalidates the cache:
  expect_null(cache$get(fake_api_client(cl$addr, FALSE)))
  expect_equal(cache$list(), character())
})


test_that("multiple servers", {
  cache <- token_cache$new()
  cl1 <- fake_api_client("a", TRUE)
  cl2 <- fake_api_client("b", TRUE)
  t1 <- fake_token()
  t2 <- fake_token()

  cache$set(cl1, t1)
  cache$set(cl2, t2)

  expect_setequal(cache$list(), c(cl1$addr, cl2$addr))
  expect_equal(cache$get(cl1, TRUE), t1)
  expect_equal(cache$get(cl2, TRUE), t2)

  cache$clear()
  expect_equal(cache$list(), character())
})


test_that("delete", {
  cache <- token_cache$new()
  cl1 <- fake_api_client("a", TRUE)
  cl2 <- fake_api_client("b", TRUE)
  t1 <- fake_token()
  t2 <- fake_token()

  cache$set(cl1, t1)
  cache$set(cl2, t2)

  cache$delete(cl1)

  expect_setequal(cache$list(), c(cl2$addr))
})


test_that("token_only skips cache", {
  srv <- test_vault_test_server()
  cl <- srv$client()
  vault_env$cache$clear()
  cl$auth$enable("userpass", "user / password based auth")
  cl$auth$userpass$write("rich", "pass")

  cl2 <- srv$client(login = FALSE)
  cl2$login(username = "rich", password = "pass", method = "userpass",
            quiet = TRUE)

  t <- cl2$login(username = "rich", password = "pass", method = "userpass",
                 token_only = TRUE, quiet = TRUE)
  expect_false(t == cl2$token$client())
  expect_equal(vault_env$cache$get(cl2$api()), cl2$token$client())
})


test_that("token_only works with no cache", {
  srv <- test_vault_test_server()
  cl <- srv$client()
  vault_env$cache$clear()
  cl$auth$enable("userpass", "user / password based auth")
  cl$auth$userpass$write("rich", "pass")

  cl2 <- srv$client(login = FALSE)

  t <- cl2$login(username = "rich", password = "pass", method = "userpass",
                 token_only = TRUE, quiet = TRUE)
  expect_type(t, "character")
  expect_null(cl2$token$client())
  expect_null(vault_env$cache$get(cl2$api()))
})

context("vault: auth: approle")

test_that("approle", {
  srv <- vault_test_server()
  cl <- srv$client()
  cl$auth$enable("approle")

  d <- cl$auth$list()
  expect_setequal(d$path, c("token/", "approle/"))
  expect_setequal(d$type, c("token", "approle"))

  ar <- cl$auth$approle
  expect_equal(ar$role_list(), character(0))
})


test_that("approle auth", {
  srv <- vault_test_server()
  cl <- srv$client()
  cl$auth$enable("approle")

  role_name <- "myrole"

  ar <- cl$auth$approle
  ar$role_write(role_name)
  expect_equal(ar$role_list(), role_name)

  d <- ar$role_read(role_name)
  expect_is(d, "list")
  expect_equal(d$policies, "default")

  role_id <- ar$role_id_read(role_name)
  expect_is(role_id, "character")
  expect_equal(length(role_id), 1L)

  secret <- ar$secret_id_generate(role_name)
  expect_setequal(names(secret), c("id", "accessor"))
  auth <- ar$login(role_id, secret$id)

  token <- auth$client_token
  expect_is(token, "character")

  cl2 <- srv$client(login = FALSE)
  expect_error(cl2$login(token = token), NA)
})


test_that("custom mount", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$auth$enable("approle", path = "approle2")
  ar <- cl$auth$approle$custom_mount("approle2")
  expect_is(ar, "vault_client_auth_approle")

  ar$role_write("server")
  expect_equal(ar$role_read("server")$policies, "default")
  expect_error(cl$auth$approle$role_read("server"))
})


test_that("full login", {
  srv <- vault_test_server()
  cl <- srv$client()
  cl$auth$enable("approle")
  cl$write("/secret/test", list(a = 1))
  cl$policy$write("standard", 'path "secret/*" {\n  policy = "read"\n}')

  role_name <- "myrole"

  cl$auth$approle$role_write(role_name, policies = "standard")

  cl$auth$approle$role_read(role_name)
  role_id <- cl$auth$approle$role_id_read(role_name)
  secret <- cl$auth$approle$secret_id_generate(role_name)

  cl2 <- srv$client(login = FALSE)
  cl2$login(method = "approle",
            role_id = role_id,
            secret_id = secret$id)
  expect_equal(cl2$read("/secret/test"), list(a = 1))
  expect_error(cl2$write("/secret/test", list(a = 2)))
})


test_that("role delete", {
  srv <- vault_test_server()
  cl <- srv$client()
  cl$auth$enable("approle")

  ar <- cl$auth$approle

  ar$role_write("a")
  ar$role_write("b")
  expect_setequal(ar$role_list(), c("a", "b"))
  ar$role_delete("a")
  expect_equal(ar$role_list(), "b")
})


test_that("role set id", {
  srv <- vault_test_server()
  cl <- srv$client()
  cl$auth$enable("approle")

  ar <- cl$auth$approle
  role_name <- "myrole"
  role_id <- rand_str(10)

  ar$role_write(role_name)
  ar$role_id_write(role_name, role_id)
  expect_equal(ar$role_id_read(role_name), role_id)
})


test_that("secret id list", {
  srv <- vault_test_server()
  cl <- srv$client()
  cl$auth$enable("approle")

  ar <- cl$auth$approle
  role_name <- "myrole"
  ar$role_write(role_name)

  expect_equal(ar$secret_id_list(role_name), character(0))
  s1 <- ar$secret_id_generate(role_name)
  expect_equal(ar$secret_id_list(role_name), s1$accessor)
  s2 <- ar$secret_id_generate(role_name)
  expect_setequal(ar$secret_id_list(role_name),
                  c(s1$accessor, s2$accessor))
})


test_that("secret id read", {
  srv <- vault_test_server()
  cl <- srv$client()
  cl$auth$enable("approle")

  ar <- cl$auth$approle
  role_name <- "myrole"
  ar$role_write(role_name)

  metadata <- list(key = jsonlite::unbox("value"))

  s1 <- ar$secret_id_generate(role_name, metadata)
  d <- ar$secret_id_read(role_name, s1$id)
  expect_equal(d$metadata, list(key = "value"))

  expect_equal(ar$secret_id_read(role_name, s1$accessor, TRUE), d)
})


test_that("secret id delete", {
  srv <- vault_test_server()
  cl <- srv$client()
  cl$auth$enable("approle")

  ar <- cl$auth$approle
  role_name <- "myrole"
  ar$role_write(role_name)

  s1 <- ar$secret_id_generate(role_name)
  s2 <- ar$secret_id_generate(role_name)

  ar$secret_id_delete(role_name, s1$id)
  expect_equal(ar$secret_id_list(role_name), s2$accessor)

  ar$secret_id_delete(role_name, s2$accessor, TRUE)
  expect_equal(ar$secret_id_list(role_name), character(0))
})

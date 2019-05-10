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


test_that("format", {
  srv <- vault_test_server()
  cl <- srv$client(login = FALSE)

  str <- withr::with_options(list(width = 80), cl$format())
  expect_equal(str[[1]], "<vault: client>")
  expect_match(str, "login\\(.+\n", all = FALSE)

  ## recurse:
  str <- withr::with_options(list(width = 80), cl$auth$format())
  expect_true(any(grepl("Command groups:", str)))
  expect_match(str, "github:", fixed = TRUE, all = FALSE)

  ## recurse:
  str <- withr::with_options(list(width = 80), cl$audit$format())
  expect_false(any(grepl("Command groups:", str)))

  str <- withr::with_options(list(width = 80), cl$secrets$format())
  expect_true(any(grepl("Command groups:", str)))
  expect_match(str, "transit:", fixed = TRUE, all = FALSE)
})


test_that("login method", {
  withr::with_envvar(c("VAULTR_AUTH_METHOD" = NA_character_), {
    expect_null(vault_client_login_method(NULL))
    expect_null(vault_client_login_method(FALSE))
    expect_error(vault_client_login_method(TRUE),
                 "Default login method not set in 'VAULTR_AUTH_METHOD'")
    expect_equal(vault_client_login_method("token"), "token")
  })

  withr::with_envvar(c("VAULTR_AUTH_METHOD" = "github"), {
    expect_equal(vault_client_login_method(NULL), "github")
    expect_null(vault_client_login_method(FALSE))
    expect_equal(vault_client_login_method(TRUE), "github")
    expect_equal(vault_client_login_method("token"), "token")
  })
})

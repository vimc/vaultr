test_that("api", {
  srv <- test_vault_test_server()
  cl <- srv$client()

  cl$write("/secret/a", list(key = 1))

  api <- cl$api()
  expect_s3_class(api, "vault_api_client")
  expect_null(api$namespace)
  ## Unauthenticated route:
  expect_equal(api$GET("/sys/seal-status"),
               cl$operator$seal_status())

  ## Authenticated route
  d <- api$GET("/secret/a")
  expect_equal(d$data$key, 1)
})


test_that("Can send namespace with api requests", {
  skip_on_cran()
  skip_if_not_installed("mockery")
  cl <- vault_api_client$new("https://example.com", namespace = "foo")
  cl$token <- "secret"
  expect_equal(cl$namespace, "foo")
  mock_response <- structure(
    list(status_code = 204),
    class = "response")
  mock_get <- mockery::mock(mock_response)

  expect_null(cl$request(mock_get, "/some/path"))
  mockery::expect_called(mock_get, 1)
  args <- mockery::mock_args(mock_get)[[1]]
  expect_equal(args[[3]],
               httr::add_headers("X-Vault-Token" = "secret"))
  expect_equal(args[[4]],
               httr::add_headers("X-Vault-Namespace" = "foo"))
})


test_that("No namespace sent by default", {
  skip_on_cran()
  skip_if_not_installed("mockery")
  cl <- vault_api_client$new("https://example.com", namespace = NULL)
  cl$token <- "secret"
  expect_null(cl$namespace, NULL)
  mock_response <- structure(
    list(status_code = 204),
    class = "response")
  mock_get <- mockery::mock(mock_response)

  expect_null(cl$request(mock_get, "/some/path"))
  mockery::expect_called(mock_get, 1)
  args <- mockery::mock_args(mock_get)[[1]]
  expect_equal(args[[3]],
               httr::add_headers("X-Vault-Token" = "secret"))
  expect_null(args[[4]])
})


test_that("can set namespace when building client", {
  skip_on_cran()
  skip_if_not_installed("withr")
  withr::with_envvar(
    c(VAULT_NAMESPACE = "foo", VAULT_ADDR = "https://example.com"), {
      expect_equal(vault_client()$api()$namespace, "foo")
      expect_equal(vault_client(namespace = "bar")$api()$namespace, "bar")
    })

  withr::with_envvar(
    c(VAULT_NAMESPACE = NA_character_, VAULT_ADDR = "https://example.com"), {
      expect_null(vault_client()$api()$namespace)
      expect_equal(vault_client(namespace = "bar")$api()$namespace, "bar")
    })
})

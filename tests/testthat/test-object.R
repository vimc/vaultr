test_that("format", {
  x <- vault_client_object$new("my description")
  private <- environment(x$initialize)$private
  expect_equal(private$name, "object")
  expect_equal(private$description, "my description")
  expect_equal(x$format(TRUE), "my description")
  expect_equal(x$format(FALSE)[[1]], "<vault: object>")
})


test_that("help: base class", {
  x <- vault_client_object$new("my description")
  mock_help <- mockery::mock(NULL)
  mockery::stub(x$help, "utils::help", mock_help)
  x$help()
  args <- mockery::mock_args(mock_help)[[1]]
  expect_equal(args, list("vault_client_object", package = "vaultr"))
})


test_that("help: derived class", {
  other <- R6::R6Class(
    "other",
    inherit = vault_client_object,
    public = list(
      initialize = function() super$initialize("description")))
  x <- other$new()
  mock_help <- mockery::mock(NULL)
  mockery::stub(x$help, "utils::help", mock_help)
  x$help()
  args <- mockery::mock_args(mock_help)[[1]]
  expect_equal(args, list("other", package = "vaultr"))
})

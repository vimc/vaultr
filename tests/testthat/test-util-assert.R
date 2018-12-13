context("util (assert)")

test_that("assert_scalar", {
  object <- 1:5
  expect_error(assert_scalar(object), "'object' must be a scalar")

  expect_error(assert_scalar(NULL), "must be a scalar")

  expect_silent(assert_scalar(TRUE))
})

test_that("assert_length", {
  object <- 1:5
  expect_error(assert_length(object, 3), "'object' must have length 3")

  expect_error(assert_length(NULL, 3), "must have length 3")

  expect_silent(assert_length(1:3, 3))
})

test_that("assert_character", {
  object <- NULL
  expect_error(assert_character(object), "'object' must be a character")

  expect_error(assert_character(1), "must be a character")
  expect_error(assert_character(pi), "must be a character")

  expect_silent(assert_character("a"))
})

test_that("assert_is", {
  object <- NULL
  expect_error(assert_is(object, "data.frame"), "'object' must be a data.frame")

  expect_error(assert_is(1, "data.frame"), "must be a data.frame")
  expect_error(assert_is(pi, "data.frame"), "must be a data.frame")

  expect_silent(assert_is(mtcars, "data.frame"))
})

test_that("assert_named", {
  object <- 1:3
  expect_error(assert_named(object), "'object' must be named")
  names(object) <- letters[1:3]
  expect_silent(assert_named(object))
})

test_that("assert_absolute_path", {
  expect_error(assert_absolute_path("foo/bar"), "Expected an absolute path")
  expect_silent(assert_absolute_path("/foo"))
})


test_that("assert_file_exists", {
  thing <- tempfile()
  expect_error(assert_file_exists(thing),
               "The path '.+' does not exist \\(for 'thing'\\)")
  file.create(thing)
  expect_silent(assert_file_exists(thing))
})


test_that("assert_is_duration", {
  var <- "1"
  expect_error(assert_is_duration(var),
               "'1' is not a valid time duration for 'var'", fixed = TRUE)
  var <- "1h"
  expect_silent(assert_is_duration(var))
})


test_that("assert_integer", {
  expect_error(assert_integer(pi), "'pi' must be integer")
  expect_silent(assert_integer(1L))
  expect_silent(assert_integer(1))
  expect_silent(assert_integer(1 + 1e-15))
})


test_that("assert_logical", {
  expect_error(assert_logical(pi), "'pi' must be a logical")
  expect_silent(assert_logical(TRUE))
  expect_silent(assert_logical(FALSE))
})


test_that("assert_vault_version", {
  cl <- list(server_version = function() numeric_version("0.9.4"))
  expect_error(
    assert_vault_version("1.0.0", cl, "/api/path", "action"),
    "action (/api/path) requires vault version >= 1.0.0 but server is 0.9.4",
    class = "vault_invalid_version",
    fixed = TRUE)
  expect_silent(
    assert_vault_version("0.9.4", cl, "/api/path", "action"))
})


test_that("match_value", {
  expect_error(match_value("foo", letters), "must be one of")
  expect_silent(match_value("a", letters))
})

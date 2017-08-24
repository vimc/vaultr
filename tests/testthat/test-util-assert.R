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

context("util")

test_that("Sys_getenv", {
  expect_null(Sys_getenv("VAULTR_NONEXISTANT"))

  withr::with_envvar(c("VAULTR_NONEXISTANT" = 123), {
    expect_equal(Sys_getenv("VAULTR_NONEXISTANT"), "123")
    expect_equal(Sys_getenv("VAULTR_NONEXISTANT", mode = "integer"), 123L)
  })

  withr::with_envvar(c("VAULTR_NONEXISTANT" = "foo"), {
    expect_equal(Sys_getenv("VAULTR_NONEXISTANT"), "foo")
    expect_error(Sys_getenv("VAULTR_NONEXISTANT", mode = "integer"),
                 "Invalid input for integer 'foo'")
  })
})


test_that("pretty_secs", {
  expect_equal(pretty_secs(1), "1s")
  expect_equal(pretty_secs(10), "10s")
  expect_equal(pretty_secs(100), "~2m")
  expect_equal(pretty_secs(1000), "~17m")
  expect_equal(pretty_secs(10000), "~3h")
  expect_equal(pretty_secs(100000), "~1d")
  expect_equal(pretty_secs(1000000), "~12d")
})

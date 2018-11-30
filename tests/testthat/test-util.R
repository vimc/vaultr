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

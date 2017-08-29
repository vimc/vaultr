context("server manager")

test_that("disable running: cran", {
  withr::with_envvar(c(NOT_CRAN = NA_character_), {
    server <- server_manager$new()
    expect_false(server$can_run())
    expect_null(server$address)
    expect_null(server$bin)
    expect_null(vault_test_server_start())
  })
})

test_that("disable running: address", {
  testthat::skip_on_cran()

  vars <- c(NOT_CRAN = NA_character_,
            VAULTR_TEST_SERVER_PORT = NA_character_)

  withr::with_envvar(vars, {
    server <- server_manager$new()
    server$bin <- "vault"
    expect_false(server$can_run())
    expect_null(server$address)
    expect_error(server$start(), "'VAULTR_TEST_SERVER_PORT' not set",
                 fixed = TRUE)
  })
})

test_that("disable running: binary", {
  testthat::skip_on_cran()

  vars <- c(NOT_CRAN = NA_character_,
            VAULTR_TEST_SERVER_PORT = 11888)

  withr::with_envvar(vars, {
    server <- server_manager$new()
    server$bin <- NULL
    expect_false(server$can_run())
    expect_null(server$bin)
    expect_error(server$start(), "vault executable not found", fixed = TRUE)
  })
})

test_that("invalid port", {
  testthat::skip_on_cran()

  withr::with_envvar(c(VAULTR_TEST_SERVER_PORT = "one"), {
    expect_error(server_manager$new(), "Invalid port 'one'", fixed = TRUE)
  })
})

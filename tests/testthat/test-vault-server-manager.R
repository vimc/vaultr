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

test_that("install: not on CRAN", {
  withr::with_envvar(c(NOT_CRAN = NA_character_), {
    expect_error(vault_test_server_install(tempfile()),
                 "Do not run this on CRAN")
  })
})

test_that("install: opt-in", {
  testthat::skip_on_cran()
  withr::with_envvar(c(VAULTR_TEST_SERVER_INSTALL = NA_character_), {
    expect_error(vault_test_server_install(tempfile()),
                 "Please read the documentation")
  })
})

test_that("install: missing directory", {
  testthat::skip_on_cran()
  withr::with_envvar(c(VAULTR_TEST_SERVER_INSTALL = "true"), {
    expect_error(vault_test_server_install(tempfile()),
                 "must be an existing directory")
  })
})

test_that("install", {
  testthat::skip_on_cran()
  skip_if_no_internet()
  dest <- tempfile()
  dir.create(dest)
  res <- withr::with_envvar(c(VAULTR_TEST_SERVER_INSTALL = "true"), {
    vault_test_server_install(dest, TRUE)
  })
  expect_equal(res, file.path(dest, "vault"))
  expect_true(file.exists(res))
  expect_equal(dir(dest), "vault")
  expect_equal(system2(res, "-help", stdout = FALSE, stderr = FALSE), 0)
})

test_that("port collision", {
  testthat::skip_on_cran()
  skip_if_no_vault_test_server()
  server <- server_manager$new()
  expect_error(server$up(),
               "vault is already running at https://127.0.0.1:18200")
})

test_that("reinstall", {
  testthat::skip_on_cran()
  skip_if_no_internet()
  path <- tempfile()
  dir.create(path)
  dest <- file.path(path, "vault")
  writeLines("vault", dest)
  res <- withr::with_envvar(c(VAULTR_TEST_SERVER_INSTALL = "true"), {
    expect_message(vault_test_server_install(path, TRUE),
                   "vault already installed at")
  })
  expect_identical(readLines(dest), "vault")
})

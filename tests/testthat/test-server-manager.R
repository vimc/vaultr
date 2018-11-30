context("server manager")

test_that("install", {
  testthat::skip_on_cran()
  skip_if_no_internet()

  path <- tempfile()
  vars <- c(VAULT_BIN_PATH = path,
            VAULTR_TEST_SERVER_INSTALL = "true")

  res <- withr::with_envvar(vars, {
    vault_test_server_install(TRUE)
  })

  expect_equal(res, file.path(path, "vault"))
  expect_true(file.exists(res))
  expect_equal(dir(path), "vault")
  expect_equal(system2(res, "-help", stdout = FALSE, stderr = FALSE), 0)
})


test_that("reinstall", {
  testthat::skip_on_cran()
  skip_if_no_internet()

  path <- tempfile()
  vars <- c(VAULT_BIN_PATH = path,
            VAULTR_TEST_SERVER_INSTALL = "true")

  dir.create(path)
  dest <- file.path(path, "vault")
  writeLines("vault", dest)
  res <- withr::with_envvar(vars, {
    expect_message(vault_test_server_install(path, TRUE),
                   "vault already installed at")
  })
  expect_identical(readLines(dest), "vault")
})

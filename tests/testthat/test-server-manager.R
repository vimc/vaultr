test_that("safeguards for run", {
  skip_on_cran()

  withr::with_envvar(c(NOT_CRAN = NA_character_), {
    expect_null(vault_server_manager_bin())
  })

  withr::with_envvar(c(VAULTR_TEST_SERVER_BIN_PATH = NA_character_), {
    expect_null(vault_server_manager_bin())
  })

  withr::with_envvar(c(VAULTR_TEST_SERVER_BIN_PATH = tempfile()), {
    expect_null(vault_server_manager_bin())
  })

  path <- tempfile()
  file.create(path)
  withr::with_envvar(c(VAULTR_TEST_SERVER_BIN_PATH = path), {
    expect_null(vault_server_manager_bin())
  })

  path <- tempfile()
  dir.create(path)
  withr::with_envvar(c(VAULTR_TEST_SERVER_BIN_PATH = path), {
    expect_null(vault_server_manager_bin())
  })

  vault <- file.path(path, vault_exe_filename())
  file.create(vault)
  withr::with_envvar(c(VAULTR_TEST_SERVER_BIN_PATH = path), {
    expect_equal(normalizePath(vault_server_manager_bin()),
                 normalizePath(vault))
  })

  withr::with_envvar(c(VAULTR_TEST_SERVER_PORT = NA_character_), {
    expect_equal(vault_server_manager_port(), 18200L)
  })
  withr::with_envvar(c(VAULTR_TEST_SERVER_PORT = "1000"), {
    expect_equal(vault_server_manager_port(), 1000)
  })
  withr::with_envvar(c(VAULTR_TEST_SERVER_PORT = "port"), {
    expect_error(vault_server_manager_port(), "Invalid port 'port'")
  })
})


test_that("disabled server manager", {
  res <- vault_server_manager$new(NULL)
  expect_false(res$enabled)
  expect_equal(res$new_server(if_disabled = identity),
               "vault is not enabled")
  expect_error(res$new_server(if_disabled = stop),
               "vault is not enabled")
})


test_that("timeout catch", {
  test <- function() FALSE
  path <- tempfile()
  txt <- c("information about the process",
           "on two lines")
  writeLines(txt, path)
  process <- list(is_alive = function() FALSE,
                  get_error_file = function() path)
  expect_error(vault_server_wait(test, process),
               paste(c("vault has died:", txt), collapse = "\n"),
               fixed = TRUE)
})


test_that("vault_platform", {
  expect_equal(vault_platform("Darwin"), "darwin")
  expect_equal(vault_platform("Windows"), "windows")
  expect_equal(vault_platform("Linux"), "linux")
  expect_error(vault_platform("Solaris"), "Unknown sysname")
})


test_that("env", {
  srv <- test_vault_test_server()
  env <- srv$env()
  expect_equal(env[["VAULT_ADDR"]], srv$addr)
  expect_equal(env[["VAULT_TOKEN"]], srv$token)
  expect_equal(env[["VAULTR_AUTH_METHOD"]], "token")
  expect_equal(env[["VAULT_CACERT"]], NA_character_)
  expect_setequal(names(env),
                  c("VAULT_ADDR", "VAULT_TOKEN", "VAULT_CACERT",
                    "VAULTR_AUTH_METHOD"))

  env[] <- NA_character_
  withr::with_envvar(env, {
    srv$export()
    expect_equal(Sys.getenv("VAULT_ADDR"), srv$addr)
    expect_equal(Sys.getenv("VAULT_TOKEN"), srv$token)
    expect_equal(Sys.getenv("VAULTR_AUTH_METHOD"), "token")
    expect_identical(Sys.getenv("VAULT_CACERT", NA_character_), NA_character_)
  })
})


test_that("clear tokens", {
  srv <- test_vault_test_server()
  vault_env$cache$clear()

  cl <- srv$client()
  cl$auth$enable("userpass")
  cl$auth$userpass$write("alice", "password")
  cl2 <- srv$client(login = FALSE)
  cl2$login(method = "userpass", username = "alice", password = "password",
            quiet = TRUE)

  expect_equal(vault_env$cache$list(), srv$addr)
  srv$clear_cached_token()
  expect_equal(vault_env$cache$list(), character(0))
})


test_that("skip if server does not come up", {
  testthat::skip_on_cran()
  testthat::skip_on_os("windows")
  tmp <- withr::local_tempfile()
  file.create(tmp)
  port <- vault_server_manager_port() + 20
  mgr <- vault_server_manager$new(tmp, port)
  err <- tryCatch(mgr$new_server(),
                  condition = identity)
  expect_s3_class(err, "skip")
  expect_match(err$message, "vault server failed to start")
})


test_that("correct exe on different platforms", {
  expect_equal(vault_exe_filename("windows"), "vault.exe")
  expect_equal(vault_exe_filename("linux"), "vault")
  expect_equal(vault_exe_filename("darwin"), "vault")
})

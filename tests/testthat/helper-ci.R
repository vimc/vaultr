if (identical(Sys.getenv("CI"), "true") &&
    identical(Sys.getenv("NOT_CRAN"), "true") &&
    identical(Sys.getenv("VAULTR_TEST_SERVER_INSTALL"), "true") &&
    !nzchar(Sys.getenv("GITHUB_WORKSPACE"))) {
  Sys.setenv(VAULTR_TEST_SERVER_BIN_PATH =
               sprintf("%s/.vault", Sys.getenv("GITHUB_WORKSPACE")))
  vault_test_server_install()
}

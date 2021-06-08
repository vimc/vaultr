if (identical(Sys.getenv("CI"), "true") &&
    identical(Sys.getenv("NOT_CRAN"), "true") &&
    identical(Sys.getenv("VAULTR_TEST_SERVER_INSTALL"), "true")) {
  vault_test_server_install()
}

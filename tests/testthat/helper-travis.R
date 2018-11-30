if (identical(Sys.getenv("TRAVIS"), "true") &&
    identical(Sys.getenv("VAULTR_TEST_SERVER_INSTALL"), "true")) {
  vault_test_server_install()
}

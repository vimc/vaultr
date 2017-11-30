## Unset things that might be set by users and would interfere with
## testing (or worse, cause the testing to interfere with their vault
## instance).
Sys.unsetenv("VAULTR_CACHE_DIR")
Sys.unsetenv("VAULT_ADDR")

if (identical(Sys.getenv("TRAVIS"), "true") &&
    identical(Sys.getenv("VAULTR_TEST_SERVER_INSTALL"), "true")) {
  vault_test_server_install()
}
vault_test_server_start()

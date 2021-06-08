## NOTE: Windows should be possible, but we end up with
## VAULTR_TEST_SERVER_BIN_PATH not set despite the workflow setting
## it.
if (identical(Sys.getenv("CI"), "true") &&
    identical(Sys.getenv("NOT_CRAN"), "true") &&
    tolower(Sys.info()[["sysname"]]) != "windows" &&
    identical(Sys.getenv("VAULTR_TEST_SERVER_INSTALL"), "true")) {
  vault_test_server_install()
}

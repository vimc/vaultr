context("resolve-secrets")

test_that("vault secrets can be resolved", {
  srv <- vaultr::vault_test_server()
  cl <- srv$client()
  cl$write("/secret/users/alice", list(password = "ALICE"))
  cl$write("/secret/users/bob", list(password = "BOB"))
  
  config <- list(path = tempfile(),
                 vault_server = srv$addr)
  
  x <- list(name = "alice",
            password = "VAULT:/secret/users/alice:password")
  withr::with_envvar(c(VAULTR_AUTH_METHOD = NA_character_), {
    expect_error(resolve_secrets(x, addr = config$vault_server),
                 "Default login method not set in 'VAULTR_AUTH_METHOD'")
  })
  withr::with_envvar(c(VAULTR_AUTH_METHOD = "token", VAULT_TOKEN = NA), {
    expect_error(resolve_secrets(x, addr = config$vault_server), 
                 "Vault token was not found")
  })
  withr::with_envvar(c(VAULTR_AUTH_METHOD = "token", VAULT_TOKEN = "fake"), {
    expect_error(resolve_secrets(x, addr = config$vault_server),
                 "Token login failed with error")
  })
  
  withr::with_envvar(c(VAULTR_AUTH_METHOD = "token", VAULT_TOKEN = srv$token), {
    expect_equal(resolve_secrets(x, addr = config$vault_server),
                 list(name = "alice", password = "ALICE"))
    expect_equal(resolve_secrets(unlist(x), addr = config$vault_server),
                 list(name = "alice", password = "ALICE"))
  })
})
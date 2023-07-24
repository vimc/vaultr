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
    expect_error(vault_resolve_secrets(x, addr = config$vault_server),
                 "Default login method not set in 'VAULTR_AUTH_METHOD'")
  })
  withr::with_envvar(c(VAULTR_AUTH_METHOD = "token", VAULT_TOKEN = NA), {
    expect_error(vault_resolve_secrets(x, addr = config$vault_server),
                 "Vault token was not found")
  })
  withr::with_envvar(c(VAULTR_AUTH_METHOD = "token", VAULT_TOKEN = "fake"), {
    expect_error(vault_resolve_secrets(x, addr = config$vault_server),
                 "Token login failed with error")
  })

  withr::with_envvar(c(VAULTR_AUTH_METHOD = "token", VAULT_TOKEN = srv$token), {
    expect_equal(vault_resolve_secrets(x, addr = config$vault_server),
                 list(name = "alice", password = "ALICE"))
    expect_equal(vault_resolve_secrets(unlist(x), addr = config$vault_server),
                 list(name = "alice", password = "ALICE"))
  })

  withr::with_envvar(c(VAULTR_AUTH_METHOD = NA_character_), {
    args <- list(login = "token", token = srv$token, addr = config$vault_server)
    expect_equal(vault_resolve_secrets(x, vault_args = args),
                 list(name = "alice", password = "ALICE"))
    expect_error(
      vault_resolve_secrets(x, vault_args = args, addr = "somewhere"),
      "Do not provide both '...' and 'vault_args'", fixed = TRUE)
  })
})


test_that("Provide better error messages when failing to read", {
  srv <- vaultr::vault_test_server()
  cl <- srv$client()
  cl$write("/secret/users/alice", list(password = "ALICE"))
  cl$write("/secret/users/bob", list(password = "BOB"))

  rules <- paste('path "secret/users/alice" {',
                 '  policy = "read"',
                 "}",
                 sep = "\n")
  cl$policy$write("read-secret-alice", rules)
  token <- cl$token$create(policies = "read-secret-alice")

  x <- list(alice = "VAULT:/secret/users/alice:password",
            bob = "VAULT:/secret/users/bob:password")

  args <- list(login = "token", token = token, addr = srv$addr)
  expect_error(
    vault_resolve_secrets(x, vault_args = args),
    "While reading secret/users/bob:",
    class = "vault_forbidden")
})

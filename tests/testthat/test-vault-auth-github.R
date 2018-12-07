context("vault: auth: github")

test_that("custom mount", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$auth$enable("github", path = "github2")
  gh <- cl$auth$github$custom_mount("github2")
  expect_is(gh, "vault_client_auth_github")

  gh$configure(organization = "vimc")
  expect_equal(gh$configuration()$organization, "vimc")
  expect_error(cl$auth$github$configuration()$organization)
})


test_that("github set policy: group", {
  srv <- vault_test_server()
  cl <- srv$client()
  cl$auth$enable("github")
  cl$auth$github$configure(organization = "vimc")
  cl$auth$github$write("robots", "default")
  d <- cl$auth$github$read("robots")
  expect_equal(d$value, "default")
  expect_equal(cl$read("/auth/github/map/teams/robots"), d)
})


test_that("github set policy: group", {
  srv <- vault_test_server()
  cl <- srv$client()
  cl$auth$enable("github")
  cl$auth$github$configure(organization = "vimc")
  cl$auth$github$write("richfitz", "default", TRUE)

  d <- cl$auth$github$read("richfitz", TRUE)
  expect_equal(d$value, "default")
  expect_equal(cl$read("/auth/github/map/users/richfitz"), d)
})


## In github.com/settings/token for vimc-robot, with label "vaultr-testing"
##
## Integration test - this one is (lots) slower because it calls out
## to github.  So we do all the bits in here that want to be run after
## authenticating with github.
test_that("github auth", {
  skip_if_no_vaultr_test_github_pat()
  skip_if_no_internet()
  gh_token <- vaultr_test_github_pat()

  srv <- vault_test_server()
  cl <- srv$client()

  ## Set up a basic policy:
  cl$policy$write("standard", 'path "secret/a/*" {\n  policy = "write"\n}')

  ## Configure github:
  cl$auth$enable("github")
  cl$auth$github$configure(organization = "vimc")
  cl$auth$github$write("vimc-robot", "standard", TRUE)
  cl$auth$github$read("vimc-robot", TRUE)

  ## Login:
  auth <- cl$auth$github$login(token = gh_token)
  token <- auth$client_token

  ## Check our token:
  cl2 <- srv$client(login = FALSE)
  cl2$login(token = token)
  expect_true("standard" %in% cl2$token$lookup_self()$policies)

  ## Can we read and write where expected:
  cl2$write("secret/a/b", list(value = 1))
  expect_equal(cl2$read("secret/a/b"), list(value = 1))

  ## Are we forbidden where expected:
  err <- tryCatch(cl2$write("secret/b", list(value = 1)), error = identity)
  expect_is(err, "vault_error")
  expect_is(err, "vault_forbidden")
})

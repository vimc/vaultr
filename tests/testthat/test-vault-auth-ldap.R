context("vault: auth: ldap")

test_that("basic auth", {
  srv <- vault_test_server()
  cl <- srv$client()
  cl$auth$enable("ldap", "ldap based auth")
  d <- cl$auth$list()
  expect_setequal(d$path, c("token/", "ldap/"))
  expect_setequal(d$type, c("token", "ldap"))

  cl2 <- srv$client(login = FALSE)
  expect_error(cl2$login(method = "ldap",
                         username = "rich",
                         password = "password"))

  cl$write("/auth/ldap/users/rich",
           list(password = "password", policies = "admins"))
  cl2$login(method = "ldap",
            username = "rich",
            password = "password")

  expect_equal(cl$list("auth/ldap/users"), "rich")
})


test_that("ldap", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$auth$enable("ldap", "ldap based auth")
  expect_true("ldap" %in% cl$auth$list()$type)
  expect_equal(cl$auth$ldap$list(), character(0))

  cl$auth$ldap$write("rich", "pass")
  expect_equal(cl$auth$ldap$list(), "rich")

  d <- cl$auth$ldap$read("rich")
  expect_equal(d$policies, character(0))

  expect_error(cl$auth$ldap$login("rich", "wrong"))
  expect_silent(auth <- cl$auth$ldap$login("rich", "pass"))
  token <- auth$client_token
  expect_is(token, "character")

  cl2 <- srv$client(login = FALSE)
  expect_error(cl2$login(token = token), NA)
})


test_that("custom mount", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$auth$enable("ldap", path = "userpass2")
  up <- cl$auth$ldap$custom_mount("userpass2")
  expect_is(up, "vault_client_auth_ldap")

  up$write("rich", "pass")
  expect_equal(up$read("rich")$policies, character(0))
  expect_error(cl$auth$ldap$read("rich"))
})


test_that("login", {
  srv <- vault_test_server()
  cl <- srv$client()

  token <- cl$token$client()

  cl$auth$enable("ldap", "ldap based auth")
  cl$auth$ldap$write("rich", "pass", "default")

  cl2 <- srv$client(login = FALSE)
  cl2$login(method = "ldap",
            username = "rich", password = "pass")
})


test_that("request password", {
  skip_if_not_installed("mockery")

  mockery::stub(ldap_data, "read_password", function(prompt) {
    message(prompt)
    "pass"
  })
  expect_equal(ldap_data("user", NULL),
               list(username = "user", password = "pass"))
  expect_message(ldap_data("user", NULL),
                 "Password for 'user': ")
  expect_equal(ldap_data("user", "other"),
               list(username = "user", password = "other"))
  expect_silent(ldap_data("user", "other"))
})


test_that("request password, level 2", {
  skip_if_not_installed("mockery")

  getpass <- mockery::mock("pass")
  mockery::stub(read_password, "getPass::getPass", getpass)
  expect_equal(read_password("prompt: "), "pass")
  expect_equal(mockery::mock_args(getpass)[[1]],
               list("prompt: ", TRUE))
})


test_that("update password", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$auth$enable("ldap", "ldap based auth")
  cl$auth$ldap$write("rich", "pass")
  cl$auth$ldap$update_password("rich", "word")

  expect_error(cl$auth$ldap$login("rich", "pass"))
  expect_silent(cl$auth$ldap$login("rich", "word"))
})


test_that("update policies", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$auth$enable("ldap", "ldap based auth")
  cl$auth$ldap$write("rich", "pass")
  expect_equal(cl$auth$ldap$read("rich")$policies, character(0))

  cl$auth$ldap$update_policies("rich", "root")
  expect_equal(cl$auth$ldap$read("rich")$policies, "root")
})


test_that("delete user", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$auth$enable("ldap", "ldap based auth")
  cl$auth$ldap$write("rich", "pass")
  cl$auth$ldap$delete("rich")
  expect_equal(cl$auth$ldap$list(), character(0))
  expect_error(cl$auth$ldap$login("rich", "pass"))
})


test_that("create with policy", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$policy$write("standard", 'path "secret/a/*" {\n  policy = "write"\n}')

  cl$auth$enable("ldap", "ldap based auth")
  cl$auth$ldap$write("rich", "pass", "standard")

  expect_equal(cl$auth$ldap$read("rich")$policies, "standard")

  token <- cl$auth$ldap$login("rich", "pass")$client_token

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


test_that("update policy", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$policy$write("standard", 'path "secret/a/*" {\n  policy = "write"\n}')

  cl$auth$enable("ldap", "ldap based auth")
  cl$auth$ldap$write("rich", "pass")

  cl$auth$ldap$update_policies("rich", "standard")
  token <- cl$auth$ldap$login("rich", "pass")$client_token

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


test_that("disable", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$auth$enable("ldap", "ldap based auth")
  cl$auth$disable("ldap")
  err <- tryCatch(cl$auth$ldap$write("rich", "pass"), error = identity)
  expect_is(err, "vault_invalid_path")
})


test_that("login, custom mount", {
  srv <- vault_test_server()
  cl <- srv$client()

  path <- "userpass2"
  cl$auth$enable("ldap", path = path)
  cl$auth$ldap$custom_mount(path)$write("rich", "pass")

  cl2 <- srv$client(login = FALSE)
  cl2$login(username = "rich", password = "pass",
            method = "ldap", mount = path)
  expect_equal(cl2$token$lookup_self()$meta$username, "rich")
})

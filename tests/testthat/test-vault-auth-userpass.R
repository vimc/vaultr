context("vault: auth: userpass")

test_that("basic auth", {
  srv <- vault_test_server()
  cl <- srv$client()
  cl$auth$enable("userpass", "user / password based auth")
  d <- cl$auth$list()
  expect_setequal(d$path, c("token/", "userpass/"))
  expect_setequal(d$type, c("token", "userpass"))

  cl2 <- srv$client(login = FALSE)
  expect_error(cl2$login(method = "userpass",
                         username = "rich",
                         password = "password"))

  cl$write("/auth/userpass/users/rich",
           list(password = "password", policies = "admins"))
  t <- cl2$login(method = "userpass",
                 username = "rich",
                 password = "password")
  expect_is(t, "character")
  expect_match(t, "^[-[:xdigit:]]+$")

  expect_equal(cl$list("auth/userpass/users"), "rich")
})


test_that("userpass", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$auth$enable("userpass", "user / password based auth")
  expect_true("userpass" %in% cl$auth$list()$type)
  expect_equal(cl$auth$userpass$list(), character(0))

  cl$auth$userpass$add("rich", "pass")
  expect_equal(cl$auth$userpass$list(), "rich")

  d <- cl$auth$userpass$read("rich")
  expect_equal(d$policies, character(0))

  expect_error(cl$auth$userpass$login("rich", "wrong"))
  expect_silent(auth <- cl$auth$userpass$login("rich", "pass"))
  token <- auth$client_token
  expect_is(token, "character")
  expect_match(token, "^[-[:xdigit:]]+$")

  cl2 <- srv$client(login = FALSE)
  expect_error(cl2$login(token = token), NA)
})


test_that("login", {
  srv <- vault_test_server()
  cl <- srv$client()

  token <- cl$token$client()

  cl$auth$enable("userpass", "user / password based auth")
  cl$auth$userpass$add("rich", "pass", "default")

  cl2 <- srv$client(login = FALSE)
  cl2$login(method = "userpass",
            username = "rich", password = "pass")
})


test_that("request password", {
  skip_if_not_installed("mockery")

  mockery::stub(userpass_data, "read_password", function(prompt) {
    message(prompt)
    "pass"
  })
  expect_equal(userpass_data("user", NULL),
               list(username = "user", password = "pass"))
  expect_message(userpass_data("user", NULL),
                 "Password for 'user': ")
  expect_equal(userpass_data("user", "other"),
               list(username = "user", password = "other"))
  expect_silent(userpass_data("user", "other"))
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

  cl$auth$enable("userpass", "user / password based auth")
  cl$auth$userpass$add("rich", "pass")
  cl$auth$userpass$update_password("rich", "word")

  expect_error(cl$auth$userpass$login("rich", "pass"))
  expect_silent(cl$auth$userpass$login("rich", "word"))
})


test_that("update policies", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$auth$enable("userpass", "user / password based auth")
  cl$auth$userpass$add("rich", "pass")
  expect_equal(cl$auth$userpass$read("rich")$policies, character(0))

  cl$auth$userpass$update_policies("rich", "root")
  expect_equal(cl$auth$userpass$read("rich")$policies, "root")
})


test_that("delete user", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$auth$enable("userpass", "user / password based auth")
  cl$auth$userpass$add("rich", "pass")
  cl$auth$userpass$delete("rich")
  expect_equal(cl$auth$userpass$list(), character(0))
  expect_error(cl$auth$userpass$login("rich", "pass"))
})

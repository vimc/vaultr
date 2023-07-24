test_that("basic auth", {
  srv <- test_vault_test_server()
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
  cl2$login(method = "userpass",
            username = "rich",
            password = "password",
            quiet = TRUE)

  expect_equal(cl$list("auth/userpass/users"), "rich")
})


test_that("userpass", {
  srv <- test_vault_test_server()
  cl <- srv$client()

  cl$auth$enable("userpass", "user / password based auth")
  expect_true("userpass" %in% cl$auth$list()$type)
  expect_equal(cl$auth$userpass$list(), character(0))

  cl$auth$userpass$write("rich", "pass")
  expect_equal(cl$auth$userpass$list(), "rich")

  d <- cl$auth$userpass$read("rich")
  expect_equal(d$policies, character(0))

  expect_error(cl$auth$userpass$login("rich", "wrong"))
  expect_silent(auth <- cl$auth$userpass$login("rich", "pass"))
  token <- auth$client_token
  expect_type(token, "character")

  cl2 <- srv$client(login = FALSE)
  expect_error(cl2$login(token = token, quiet = TRUE), NA)
})


test_that("custom mount", {
  srv <- test_vault_test_server()
  cl <- srv$client()

  cl$auth$enable("userpass", path = "userpass2")
  up <- cl$auth$userpass$custom_mount("userpass2")
  expect_s3_class(up, "vault_client_auth_userpass")

  up$write("rich", "pass")
  expect_equal(up$read("rich")$policies, character(0))
  expect_error(cl$auth$userpass$read("rich"))
})


test_that("login", {
  srv <- test_vault_test_server()
  cl <- srv$client()

  token <- cl$token$client()

  cl$auth$enable("userpass", "user / password based auth")
  cl$auth$userpass$write("rich", "pass", "default")

  cl2 <- srv$client(login = FALSE)
  cl2$login(method = "userpass",
            username = "rich", password = "pass", quiet = TRUE)
})


test_that("request password", {
  skip_if_not_installed("mockery")

  mockery::stub(userpass_data, "read_password", function(prompt) {
    message(prompt)
    "pass"
  })
  res <- testthat::evaluate_promise(userpass_data("user", NULL))
  expect_equal(res$result, list(username = "user", password = "pass"))
  expect_equal(res$messages, "Password for 'user': \n")

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
  srv <- test_vault_test_server()
  cl <- srv$client()

  cl$auth$enable("userpass", "user / password based auth")
  cl$auth$userpass$write("rich", "pass")
  cl$auth$userpass$update_password("rich", "word")

  expect_error(cl$auth$userpass$login("rich", "pass"))
  expect_silent(cl$auth$userpass$login("rich", "word"))
})


test_that("update policies", {
  srv <- test_vault_test_server()
  cl <- srv$client()

  cl$auth$enable("userpass", "user / password based auth")
  cl$auth$userpass$write("rich", "pass")
  expect_equal(cl$auth$userpass$read("rich")$policies, character(0))

  cl$auth$userpass$update_policies("rich", "root")
  expect_equal(cl$auth$userpass$read("rich")$policies, "root")
})


test_that("delete user", {
  srv <- test_vault_test_server()
  cl <- srv$client()

  cl$auth$enable("userpass", "user / password based auth")
  cl$auth$userpass$write("rich", "pass")
  cl$auth$userpass$delete("rich")
  expect_equal(cl$auth$userpass$list(), character(0))
  expect_error(cl$auth$userpass$login("rich", "pass"))
})


test_that("create with policy", {
  srv <- test_vault_test_server()
  cl <- srv$client()

  cl$policy$write("standard", 'path "secret/a/*" {\n  policy = "write"\n}')

  cl$auth$enable("userpass", "user / password based auth")
  cl$auth$userpass$write("rich", "pass", "standard")

  expect_equal(cl$auth$userpass$read("rich")$policies, "standard")

  token <- cl$auth$userpass$login("rich", "pass")$client_token

  cl2 <- srv$client(login = FALSE)
  cl2$login(token = token, quiet = TRUE)
  expect_true("standard" %in% cl2$token$lookup_self()$policies)

  ## Can we read and write where expected:
  cl2$write("secret/a/b", list(value = 1))
  expect_equal(cl2$read("secret/a/b"), list(value = 1))

  ## Are we forbidden where expected:
  err <- tryCatch(cl2$write("secret/b", list(value = 1)), error = identity)
  expect_s3_class(err, "vault_error")
  expect_s3_class(err, "vault_forbidden")
})


test_that("update policy", {
  srv <- test_vault_test_server()
  cl <- srv$client()

  cl$policy$write("standard", 'path "secret/a/*" {\n  policy = "write"\n}')

  cl$auth$enable("userpass", "user / password based auth")
  cl$auth$userpass$write("rich", "pass")

  cl$auth$userpass$update_policies("rich", "standard")
  token <- cl$auth$userpass$login("rich", "pass")$client_token

  cl2 <- srv$client(login = FALSE)
  cl2$login(token = token, quiet = TRUE)
  expect_true("standard" %in% cl2$token$lookup_self()$policies)

  ## Can we read and write where expected:
  cl2$write("secret/a/b", list(value = 1))
  expect_equal(cl2$read("secret/a/b"), list(value = 1))

  ## Are we forbidden where expected:
  err <- tryCatch(cl2$write("secret/b", list(value = 1)), error = identity)
  expect_s3_class(err, "vault_error")
  expect_s3_class(err, "vault_forbidden")
})


test_that("disable", {
  srv <- test_vault_test_server()
  cl <- srv$client()

  cl$auth$enable("userpass", "user / password based auth")
  cl$auth$disable("userpass")
  err <- tryCatch(cl$auth$userpass$write("rich", "pass"), error = identity)
  expect_s3_class(err, "vault_invalid_path")
})


test_that("login, custom mount", {
  srv <- test_vault_test_server()
  cl <- srv$client()

  path <- "userpass2"
  cl$auth$enable("userpass", path = path)
  cl$auth$userpass$custom_mount(path)$write("rich", "pass")

  cl2 <- srv$client(login = FALSE)
  cl2$login(username = "rich", password = "pass",
            method = "userpass", mount = path, quiet = TRUE)
  expect_equal(cl2$token$lookup_self()$meta$username, "rich")
})

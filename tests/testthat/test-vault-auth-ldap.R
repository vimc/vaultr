## See development.md (in project root) for information about the test
## setup here.

test_that("custom mount", {
  srv <- test_vault_test_server()
  cl <- srv$client()

  cl$auth$enable("ldap", path = "ldap2")
  ldap <- cl$auth$ldap$custom_mount("ldap2")
  expect_s3_class(ldap, "vault_client_auth_ldap")

  info <- ldap_configure(ldap)
  expect_equal(ldap$configuration()$binddn, info$configuration$binddn)
})


test_that("ldap set policy: group", {
  srv <- test_vault_test_server()
  cl <- srv$client()
  cl$auth$enable("ldap")
  info <- ldap_configure(cl$auth$ldap)
  cl$auth$ldap$write(info$group, "default")
  expect_equal(cl$auth$ldap$list(), info$group)
  d <- cl$auth$ldap$read(info$group)
  expect_equal(d$policies, "default")
})


test_that("ldap set policy: user", {
  srv <- test_vault_test_server()
  cl <- srv$client()
  cl$auth$enable("ldap")
  info <- ldap_configure(cl$auth$ldap)
  cl$auth$ldap$write(info$username, "default", TRUE)
  expect_equal(cl$auth$ldap$list(TRUE), info$username)

  d <- cl$auth$ldap$read(info$username, TRUE)
  expect_equal(d$policies, "default")
})


test_that("delete group", {
  srv <- test_vault_test_server()
  cl <- srv$client()
  cl$auth$enable("ldap")
  info <- ldap_configure(cl$auth$ldap)
  cl$auth$ldap$write(info$group, "default")
  cl$auth$ldap$delete(info$group)
  expect_equal(cl$auth$ldap$list(), character(0))
})


test_that("delete user", {
  srv <- test_vault_test_server()
  cl <- srv$client()
  cl$auth$enable("ldap")
  info <- ldap_configure(cl$auth$ldap)
  cl$auth$ldap$write(info$group, "default", TRUE)
  cl$auth$ldap$delete(info$group, TRUE)
  expect_equal(cl$auth$ldap$list(TRUE), character(0))
})


test_that("can use ldap", {
  srv <- test_vault_test_server()
  cl <- srv$client()
  cl$auth$enable("ldap")
  d <- cl$auth$list()
  expect_setequal(d$path, c("token/", "ldap/"))
  expect_setequal(d$type, c("token", "ldap"))

  cl$policy$write("example", 'path "secret/a/*" {\n  policy = "write"\n}')

  info <- ldap_configure(cl$auth$ldap)
  cl$auth$ldap$write(info$group, "example")

  result <- cl$auth$ldap$login(username = info$username,
                               password = info$password)
  expect_true("example" %in% result$policies)
  token <- result$client_token

  cl2 <- srv$client(login = FALSE)
  cl2$login(token = token, use_cache = FALSE, quiet = TRUE)
  expect_true("example" %in% cl2$token$lookup_self()$policies)
  cl2$write("secret/a/thing", list(a = 1))

  cl3 <- srv$client(login = FALSE)
  cl3$login(method = "ldap", use_cache = FALSE, quiet = TRUE,
            username = info$username, password = info$password)
  expect_equal(cl3$read("secret/a/thing"), list(a = 1))
})

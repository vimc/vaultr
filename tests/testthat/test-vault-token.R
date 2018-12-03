context("vault: token")


test_that("capabilities-self", {
  srv <- vault_test_server()
  cl <- srv$client()
  expect_equal(cl$token$capabilities("/secret", NULL),
               list("/secret" = "root"))
  expect_equal(cl$token$capabilities("secret", NULL),
               list("secret" = "root"))
  expect_equal(cl$token$capabilities(c("secret", "/secret"), NULL),
               list("secret" = "root", "/secret" = "root"))
})


test_that("create token", {
  srv <- vault_test_server()
  cl <- srv$client()

  res <- cl$token$create(ttl = "1h")

  cl2 <- srv$client(login = FALSE)
  cl2$login(token = res)
})


test_that("lookup", {
  srv <- vault_test_server()
  cl <- srv$client()

  token <- cl$token$client()
  data <- cl$token$lookup(token)

  expect_equal(data$policies, "root")
})
